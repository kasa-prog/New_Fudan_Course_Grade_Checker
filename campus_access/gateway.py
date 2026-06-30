"""Campus network gateway: aTrust first, WebVPN fallback, direct for local runs."""

import os

import requests

from . import config
from .atrust import ATrustSession
from .webvpn import WebVPNSession


class DirectSession:
    """Plain HTTP session for on-campus or already-routed networks."""

    mode = "direct"

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.USER_AGENT})

    def get(self, url: str, **kwargs):
        kwargs.setdefault("timeout", 60)
        return self.session.get(url, **kwargs)

    def post(self, url: str, **kwargs):
        kwargs.setdefault("timeout", 60)
        return self.session.post(url, **kwargs)


def _resolve_backends(mode: str) -> list[str]:
    if mode == "auto":
        return ["atrust", "webvpn", "direct"]
    if mode in {"atrust", "webvpn", "direct"}:
        return [mode]
    raise ValueError(
        f"Unsupported CAMPUS_ACCESS={mode!r}; use auto, atrust, webvpn, or direct"
    )


def connect_grade_session(student_id: str | None = None, password: str | None = None):
    """Return (client, backend_name). Client exposes get/post like requests.Session."""
    student_id = student_id or os.environ.get("StuId", "")
    password = password or os.environ.get("UISPsw", "")
    if not student_id or not password:
        raise ValueError("StuId and UISPsw are required")

    backends = _resolve_backends(config.CAMPUS_ACCESS)
    errors: list[str] = []

    for backend in backends:
        if backend == "atrust" and not os.environ.get("ATRUST_PORTAL", "").strip():
            print("[*] Skipping aTrust backend: ATRUST_PORTAL is not configured")
            continue
        print(f"[*] Trying campus access backend: {backend}")
        try:
            if backend == "atrust":
                client = ATrustSession().connect_for_grades(student_id, password)
            elif backend == "webvpn":
                client = WebVPNSession().connect_for_grades(student_id, password)
            else:
                client = DirectSession()
            print(f"[+] Campus access established via {client.mode}")
            return client, client.mode
        except Exception as exc:
            message = f"{backend}: {exc}"
            print(f"[-] {message}")
            errors.append(message)

    raise RuntimeError(
        "All campus access backends failed:\n" + "\n".join(f"  - {item}" for item in errors)
    )
