"""WebVPN access for Fudan campus resources (adapted from Fudan_iCourse_Subscriber)."""

import html as html_mod
import os
import re
from binascii import hexlify, unhexlify
from urllib.parse import quote, urljoin, urlparse

import requests
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
import base64

from . import config


def _extract_grade_sheet_id_from_response(response) -> str | None:
    candidates = [response.url, html_mod.unescape(response.text or "")]
    patterns = [
        r"semester-index/(\d+)",
        r"grade/sheet/info/(\d+)",
        r"gradeSheetId[\"'\s:=]+(\d+)",
    ]
    for candidate in candidates:
        for pattern in patterns:
            match = re.search(pattern, candidate)
            if match:
                return match.group(1)
    return None


def encrypt_host(hostname: str) -> str:
    cipher = AES.new(config.WEBVPN_AES_KEY, AES.MODE_CFB, config.WEBVPN_AES_IV, segment_size=128)
    return hexlify(cipher.encrypt(hostname.encode("utf-8"))).decode("ascii")


def get_vpn_url(url: str) -> str:
    parsed = urlparse(url)
    protocol = parsed.scheme
    hostname = parsed.hostname
    port = parsed.port
    path = parsed.path
    if parsed.query:
        path += "?" + parsed.query
    if parsed.fragment:
        path += "#" + parsed.fragment
    path = path.lstrip("/")

    encrypted = encrypt_host(hostname)
    iv_hex = hexlify(config.WEBVPN_AES_IV).decode("ascii")
    port_suffix = ""
    if port and not (
        (protocol == "http" and port == 80)
        or (protocol == "https" and port == 443)
    ):
        port_suffix = f"-{port}"

    vpn_url = f"{config.WEBVPN_BASE}/{protocol}{port_suffix}/{iv_hex}{encrypted}"
    if path:
        vpn_url += f"/{path}"
    return vpn_url


class WebVPNSession:
    """WebVPN session with fdjwgl SSO support."""

    mode = "webvpn"

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.USER_AGENT})
        self.logged_in = False

    def get(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", 60)
        return self.session.get(get_vpn_url(url), **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", 60)
        return self.session.post(get_vpn_url(url), **kwargs)

    def connect_for_grades(self, student_id: str, password: str) -> "WebVPNSession":
        self.login(student_id, password)
        probe = self.get(config.GRADE_TARGET, allow_redirects=True, timeout=30)
        grade_sheet_id = _extract_grade_sheet_id_from_response(probe)
        if grade_sheet_id:
            print("[+] fdjwgl grade portal already reachable through WebVPN")
            return self
        try:
            self.authenticate_fdjwgl(student_id, password)
        except RuntimeError as exc:
            probe_after = self.get(config.GRADE_TARGET, allow_redirects=True, timeout=30)
            if _extract_grade_sheet_id_from_response(probe_after):
                print(f"[*] fdjwgl SSO step skipped after retry probe: {exc}")
                return self
            raise
        return self

    def login(self, student_id: str, password: str) -> bool:
        print("[WebVPN 1/7] Getting authentication context...")
        lck, entity_id = self._get_auth_context()

        print("[WebVPN 2/7] Querying authentication methods...")
        auth_chain_code, request_type = self._query_auth_methods(lck, entity_id, via_webvpn=False)

        print("[WebVPN 3/7] Getting RSA public key...")
        pub_key_pem = self._get_public_key(via_webvpn=False)

        print("[WebVPN 4/7] Encrypting password...")
        encrypted_password = self._encrypt_password(password, pub_key_pem)

        print("[WebVPN 5/7] Executing authentication...")
        login_token = self._auth_execute(
            student_id,
            encrypted_password,
            lck,
            entity_id,
            auth_chain_code,
            request_type,
            via_webvpn=False,
        )

        print("[WebVPN 6/7] Getting CAS ticket...")
        ticket_url = self._get_cas_ticket(login_token, via_webvpn=False)

        print("[WebVPN 7/7] Establishing WebVPN session...")
        self._establish_session(ticket_url)
        self.logged_in = True
        print("[+] WebVPN login successful!")
        return True

    def authenticate_fdjwgl(self, student_id: str, password: str) -> bool:
        idp_vpn_base = get_vpn_url(config.IDP_BASE)
        service_url = (
            f"{config.GRADE_BASE}/student/sso/login?refer={quote(config.GRADE_TARGET, safe='')}"
        )
        auth_url = (
            f"{config.IDP_BASE}/idp/authCenter/authenticate"
            f"?service={quote(service_url, safe='')}"
        )

        print("[*] Starting fdjwgl SSO through WebVPN...")
        resp = self.session.get(get_vpn_url(auth_url), allow_redirects=False, timeout=30)

        lck = None
        entity_id = config.GRADE_BASE
        for _ in range(15):
            location = resp.headers.get("Location", "")
            if resp.status_code not in (301, 302, 303, 307) or not location:
                break
            lck_match = re.search(r"lck=([^&#\"']+)", location)
            entity_match = re.search(r"entityId=([^&#\"']+)", location)
            if lck_match:
                lck = lck_match.group(1)
            if entity_match:
                entity_id = requests.utils.unquote(entity_match.group(1))
            if lck:
                break
            if not location.startswith("http"):
                location = urljoin(resp.url, location)
            resp = self.session.get(location, allow_redirects=False, timeout=30)

        if not lck:
            for source in [resp.url, resp.text[:5000]]:
                match = re.search(r"lck=([^&#\"']+)", source)
                if match:
                    lck = match.group(1)
                    break

        if not lck:
            raise RuntimeError(
                f"Failed to extract lck for fdjwgl SSO (status={resp.status_code})"
            )

        auth_chain_code, request_type = self._query_auth_methods(
            lck, entity_id, via_webvpn=True, referer=f"{idp_vpn_base}/ac/"
        )
        pub_key_pem = self._get_public_key(via_webvpn=True, referer=f"{idp_vpn_base}/ac/")
        encrypted_password = self._encrypt_password(password, pub_key_pem)
        login_token = self._auth_execute(
            student_id,
            encrypted_password,
            lck,
            entity_id,
            auth_chain_code,
            request_type,
            via_webvpn=True,
            referer=f"{idp_vpn_base}/ac/",
        )
        ticket_url = self._get_cas_ticket(
            login_token, via_webvpn=True, referer=f"{idp_vpn_base}/ac/"
        )

        if not ticket_url.startswith(config.WEBVPN_BASE):
            ticket_url = get_vpn_url(ticket_url)

        resp = self.session.get(ticket_url, allow_redirects=True, timeout=90)
        print(f"[+] fdjwgl SSO completed (status={resp.status_code})")
        return True

    def _get_auth_context(self) -> tuple[str, str]:
        service_url = f"{config.WEBVPN_BASE}/login?cas_login=true"
        url = (
            f"{config.IDP_BASE}/idp/authCenter/authenticate"
            f"?service={quote(service_url, safe='')}"
        )
        resp = self.session.get(url, allow_redirects=False, timeout=30)
        location = resp.headers.get("Location", "")
        while resp.status_code in (301, 302) and "lck=" not in location:
            resp = self.session.get(location, allow_redirects=False, timeout=30)
            location = resp.headers.get("Location", "")

        if resp.status_code in (301, 302):
            location = resp.headers.get("Location", "")

        lck_match = re.search(r"[?&]lck=([^&]+)", location)
        if not lck_match:
            raise RuntimeError(
                f"Failed to extract lck from redirect (status={resp.status_code})"
            )
        return lck_match.group(1), config.WEBVPN_BASE

    def _query_auth_methods(
        self,
        lck: str,
        entity_id: str,
        via_webvpn: bool,
        referer: str | None = None,
    ) -> tuple[str, str]:
        url = f"{config.IDP_BASE}/idp/authn/queryAuthMethods"
        if via_webvpn:
            url = get_vpn_url(url)
        headers = {
            "Content-Type": "application/json",
            "Referer": referer or f"{config.IDP_BASE}/ac/",
            "Origin": config.WEBVPN_BASE if via_webvpn else config.IDP_BASE,
        }
        resp = self.session.post(
            url, json={"lck": lck, "entityId": entity_id}, headers=headers, timeout=30
        )
        data = resp.json()
        auth_method_list = data.get("data", [])
        request_type = data.get("requestType", "chain_type")
        auth_chain_code = ""
        for method in auth_method_list:
            if method.get("moduleCode") == "userAndPwd":
                auth_chain_code = method.get("authChainCode", "")
                break
        if not auth_chain_code:
            raise RuntimeError("Failed to get authChainCode")
        return auth_chain_code, request_type

    def _get_public_key(self, via_webvpn: bool, referer: str | None = None) -> str:
        url = f"{config.IDP_BASE}/idp/authn/getJsPublicKey"
        if via_webvpn:
            url = get_vpn_url(url)
        resp = self.session.get(
            url,
            headers={"Referer": referer or f"{config.IDP_BASE}/ac/"},
            timeout=30,
        )
        pub_key_b64 = resp.json().get("data", "")
        if not pub_key_b64:
            raise RuntimeError("Failed to get public key")
        return pub_key_b64

    def _encrypt_password(self, password: str, pub_key_b64: str) -> str:
        pem = (
            "-----BEGIN PUBLIC KEY-----\n"
            + pub_key_b64
            + "\n-----END PUBLIC KEY-----"
        )
        rsa_key = RSA.import_key(pem)
        cipher = PKCS1_v1_5.new(rsa_key)
        encrypted = cipher.encrypt(password.encode("utf-8"))
        return base64.b64encode(encrypted).decode("ascii")

    def _auth_execute(
        self,
        student_id: str,
        encrypted_password: str,
        lck: str,
        entity_id: str,
        auth_chain_code: str,
        request_type: str,
        via_webvpn: bool,
        referer: str | None = None,
    ) -> str:
        url = f"{config.IDP_BASE}/idp/authn/authExecute"
        if via_webvpn:
            url = get_vpn_url(url)
        payload = {
            "authModuleCode": "userAndPwd",
            "authChainCode": auth_chain_code,
            "entityId": entity_id,
            "requestType": request_type,
            "lck": lck,
            "authPara": {
                "loginName": student_id,
                "password": encrypted_password,
                "verifyCode": "",
            },
        }
        resp = self.session.post(
            url,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Referer": referer or f"{config.IDP_BASE}/ac/",
                "Origin": config.WEBVPN_BASE if via_webvpn else config.IDP_BASE,
            },
            timeout=30,
        )
        data = resp.json()
        if str(data.get("code")) != "200":
            raise RuntimeError(f"Authentication failed (code={data.get('code')})")
        login_token = data.get("loginToken", "")
        if not login_token:
            raise RuntimeError("No loginToken in response")
        return login_token

    def _get_cas_ticket(
        self, login_token: str, via_webvpn: bool, referer: str | None = None
    ) -> str:
        url = f"{config.IDP_BASE}/idp/authCenter/authnEngine"
        if via_webvpn:
            url = get_vpn_url(url)
        resp = self.session.post(
            url,
            data={"loginToken": login_token},
            headers={
                "Referer": referer or f"{config.IDP_BASE}/ac/",
                "Origin": config.WEBVPN_BASE if via_webvpn else config.IDP_BASE,
            },
            timeout=30,
        )
        ticket_match = re.search(
            r'locationValue\s*=\s*"([^"]*ticket=[^"]*)"', resp.text
        )
        if not ticket_match:
            ticket_match = re.search(
                r'(https?://[^\s"\'<>]*ticket=[^\s"\'<>]*)', resp.text
            )
        if not ticket_match:
            raise RuntimeError("Failed to extract ticket URL")
        return html_mod.unescape(ticket_match.group(1))

    def _establish_session(self, ticket_url: str):
        for attempt in range(3):
            try:
                resp = self.session.get(ticket_url, allow_redirects=True, timeout=90)
                if resp.status_code == 200:
                    for cookie in list(self.session.cookies):
                        if (
                            cookie.name.startswith("wengine_vpn_ticket")
                            and cookie.name != "wengine_vpn_ticket"
                        ):
                            self.session.cookies.set(
                                "wengine_vpn_ticket",
                                cookie.value,
                                domain=cookie.domain,
                                path=cookie.path,
                            )
                    return
                raise RuntimeError(
                    f"Failed to establish WebVPN session (status={resp.status_code})"
                )
            except requests.exceptions.Timeout:
                has_ticket = any(
                    "wengine_vpn_ticket" in c.name for c in self.session.cookies
                )
                if has_ticket:
                    return
                if attempt < 2:
                    print(f"    WebVPN timeout, retrying ({attempt + 2}/3)...")
                    continue
                raise
