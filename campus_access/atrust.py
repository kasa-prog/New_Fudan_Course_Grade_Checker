"""Fudan aTrust 2.0 web login via UIS OAuth (vpn.fudan.edu.cn)."""

import os
import re

import requests

from . import config
from .uis_auth import extract_auth_params_from_response, uis_password_login

try:
    import pyotp
except ImportError:  # pragma: no cover - optional dependency
    pyotp = None


class ATrustSession:
    """aTrust portal session established through Fudan UIS OAuth."""

    mode = "atrust"

    def __init__(self, portal: str | None = None):
        self.portal = (portal or config.ATRUST_PORTAL).rstrip("/")
        if not self.portal:
            raise ValueError("ATRUST_PORTAL is not configured")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": config.USER_AGENT,
                "Accept": "application/json, text/plain, */*",
            }
        )
        self.logged_in = False
        self.auth_config = {}

    def get(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", 60)
        return self.session.get(url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", 60)
        return self.session.post(url, **kwargs)

    def connect_for_grades(self, student_id: str, password: str) -> "ATrustSession":
        self.login(student_id, password)
        if not self._probe_campus_reachability():
            raise RuntimeError("aTrust session cannot reach fdjwgl grade portal")
        return self

    def login(self, student_id: str, password: str) -> bool:
        tid = os.environ.get("ATRUST_COOKIE_TID", "").strip()
        sig = os.environ.get("ATRUST_COOKIE_SIG", "").strip()
        if tid and sig:
            host = requests.utils.urlparse(self.portal).hostname
            if host:
                self.session.cookies.set("tid", tid, domain=host)
                self.session.cookies.set("tid.sig", sig, domain=host)

        print(f"[*] Logging into Fudan aTrust portal: {self.portal}")
        self.auth_config = self._fetch_auth_config()
        login_url = self._resolve_uis_login_url()
        print("[*] Starting Fudan UIS OAuth for aTrust (client_id=vpn)...")

        bootstrap = self.session.get(login_url, allow_redirects=True, timeout=30)
        lck, entity_id = extract_auth_params_from_response(bootstrap)
        if not lck:
            raise RuntimeError(
                f"Failed to extract UIS lck from aTrust OAuth bootstrap (status={bootstrap.status_code})"
            )
        entity_id = entity_id or config.ATRUST_UIS_ENTITY_ID

        redirect_url = uis_password_login(
            self.session,
            student_id,
            password,
            lck,
            entity_id,
            origin=config.IDP_BASE,
        )
        print("[*] Following aTrust OAuth callback...")
        callback = self.session.get(redirect_url, allow_redirects=True, timeout=60)
        if callback.status_code >= 400 and "common_error" in callback.url:
            raise RuntimeError(
                f"aTrust OAuth callback failed (status={callback.status_code}, url={callback.url})"
            )

        self._handle_followup_auth(callback)
        if not self._verify_portal_session():
            raise RuntimeError("aTrust portal session verification failed after UIS login")

        self.logged_in = True
        print("[+] Fudan aTrust login successful!")
        return True

    def _fetch_auth_config(self) -> dict:
        resp = self.session.get(
            f"{self.portal}/passport/v1/public/authConfig",
            timeout=30,
        )
        data = resp.json()
        if data.get("code") not in (0, "0"):
            raise RuntimeError(f"aTrust authConfig failed: {data.get('message') or data}")
        auth_config = data.get("data") or {}
        csrf = (auth_config.get("security") or {}).get("csrfToken")
        if csrf:
            self.session.headers["X-CSRF-Token"] = csrf
        return auth_config

    def _resolve_uis_login_url(self) -> str:
        first_auth = (self.auth_config.get("firstAuth") or [None])[0]
        if first_auth:
            return first_auth

        for server in self.auth_config.get("authServerInfoList") or []:
            if server.get("loginDomain") == config.ATRUST_AUTH_DOMAIN and server.get("loginUrl"):
                return server["loginUrl"]

        raise RuntimeError("aTrust authConfig did not expose a UIS login URL")

    def _handle_followup_auth(self, callback: requests.Response):
        next_service = None
        try:
            payload = callback.json()
            next_service = (payload.get("data") or {}).get("nextService")
        except ValueError:
            pass

        if next_service and "totp" in str(next_service).lower():
            totp_secret = os.environ.get("ATRUST_TOTP_SECRET", "").strip()
            if not totp_secret:
                raise RuntimeError("aTrust requires TOTP; set ATRUST_TOTP_SECRET")
            if pyotp is None:
                raise RuntimeError("aTrust TOTP requires pyotp package")
            code = pyotp.TOTP(totp_secret).now()
            resp = self.session.post(
                f"{self.portal}/passport/v1/public/auth/totp",
                json={"code": code},
                timeout=30,
            )
            data = resp.json()
            if data.get("code") not in (0, "0", 200, "200"):
                raise RuntimeError(f"aTrust TOTP auth failed: {data}")

    def _verify_portal_session(self) -> bool:
        try:
            resp = self.session.get(f"{self.portal}/portal/", timeout=30)
            if resp.status_code == 200:
                return True
        except requests.RequestException:
            pass
        return False

    def _probe_campus_reachability(self) -> bool:
        try:
            resp = self.get(config.GRADE_TARGET, allow_redirects=True, timeout=30)
        except requests.RequestException as exc:
            print(f"[-] aTrust grade portal probe failed: {exc}")
            return False

        if resp.status_code != 200:
            print(f"[-] aTrust grade portal probe status={resp.status_code}")
            return False

        body = resp.text or ""
        if "grade/sheet" in resp.url or "semester-index" in body or "studentGrades" in body:
            print("[+] aTrust can reach fdjwgl grade portal")
            return True

        if re.search(r"lck=", resp.url) or re.search(r"entityId=", resp.url):
            print("[*] aTrust reached fdjwgl UIS redirect (acceptable)")
            return True

        print("[-] aTrust session did not reach fdjwgl content")
        return False
