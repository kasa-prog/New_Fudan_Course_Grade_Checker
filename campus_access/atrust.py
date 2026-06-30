"""HTTP-based Sangfor aTrust portal login (best-effort, falls back to WebVPN)."""

import base64
import json
import os
import re
from urllib.parse import urlparse

import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

from . import config

try:
    import pyotp
except ImportError:  # pragma: no cover - optional dependency
    pyotp = None


class ATrustSession:
    """aTrust web portal session for reaching campus-only services."""

    mode = "atrust"

    def __init__(self, portal: str | None = None):
        self.portal = (portal or config.ATRUST_PORTAL).rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": config.USER_AGENT,
                "Accept": "application/json, text/plain, */*",
            }
        )
        self.session.verify = True
        self.logged_in = False
        self._portal_host = urlparse(self.portal).hostname or ""

    def get(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", 60)
        return self.session.get(url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", 60)
        return self.session.post(url, **kwargs)

    def connect_for_grades(self, student_id: str, password: str) -> "ATrustSession":
        self.login(student_id, password)
        if not self._probe_grade_portal():
            raise RuntimeError("aTrust session cannot reach fdjwgl grade portal")
        return self

    def login(self, student_id: str, password: str) -> bool:
        tid = os.environ.get("ATRUST_COOKIE_TID", "").strip()
        sig = os.environ.get("ATRUST_COOKIE_SIG", "").strip()
        if tid and sig and self._portal_host:
            self.session.cookies.set("tid", tid, domain=self._portal_host)
            self.session.cookies.set("tid.sig", sig, domain=self._portal_host)

        print(f"[*] Logging into aTrust portal: {self.portal}")
        self.session.get(f"{self.portal}/portal/", timeout=30)

        pub_key = self._fetch_auth_pubkey()
        encrypted_password = self._encrypt_password(password, pub_key)
        auth_result = self._password_auth(student_id, encrypted_password)
        self._handle_followup_auth(auth_result, password)
        self.logged_in = True
        print("[+] aTrust portal login successful!")
        return True

    def _fetch_auth_pubkey(self) -> str:
        candidates = [
            f"{self.portal}/passport/v1/public/authPubKey",
            f"{self.portal}/passport/v1/public/preLogin",
        ]
        last_error = None
        for url in candidates:
            try:
                resp = self.session.get(url, timeout=30)
                data = resp.json()
                pub_key = data.get("data") or data.get("pubKey") or data.get("publicKey")
                if isinstance(pub_key, dict):
                    pub_key = pub_key.get("pubKey") or pub_key.get("publicKey")
                if pub_key:
                    return pub_key
            except Exception as exc:
                last_error = exc
        raise RuntimeError(f"Failed to fetch aTrust auth public key: {last_error}")

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

    def _password_auth(self, username: str, encrypted_password: str) -> dict:
        payload = {
            "username": username,
            "password": encrypted_password,
            "captchaCode": "",
        }
        resp = self.session.post(
            f"{self.portal}/passport/v1/public/auth/password",
            json=payload,
            timeout=30,
        )
        try:
            data = resp.json()
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"aTrust password auth returned non-JSON (status={resp.status_code})"
            ) from exc

        code = data.get("code")
        if code not in (0, "0", 200, "200"):
            message = data.get("message") or data.get("msg") or data
            raise RuntimeError(f"aTrust password auth failed: {message}")
        return data

    def _handle_followup_auth(self, auth_result: dict, password: str):
        next_auth = (
            auth_result.get("nextAuth")
            or auth_result.get("nextAuthType")
            or auth_result.get("data", {}).get("nextAuth")
        )
        if not next_auth or str(next_auth).upper() in {"OK", "NONE", "0"}:
            return

        next_auth_upper = str(next_auth).upper()
        if "TOTP" in next_auth_upper:
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
            return

        raise RuntimeError(f"Unsupported aTrust follow-up auth type: {next_auth}")

    def _probe_grade_portal(self) -> bool:
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
            print("[*] aTrust reached UIS redirect for fdjwgl (acceptable)")
            return True

        print("[-] aTrust session did not reach fdjwgl content")
        return False
