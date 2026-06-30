import os

WEBVPN_BASE = "https://webvpn.fudan.edu.cn"
IDP_BASE = "https://id.fudan.edu.cn"
GRADE_BASE = "https://fdjwgl.fudan.edu.cn"
GRADE_TARGET = f"{GRADE_BASE}/student/for-std/grade/sheet/"

ATRUST_PORTAL = (
    os.environ.get("ATRUST_PORTAL", "https://vpn.fudan.edu.cn").strip().rstrip("/")
    or "https://vpn.fudan.edu.cn"
)
ATRUST_AUTH_DOMAIN = os.environ.get("ATRUST_AUTH_DOMAIN", "id.fudan.edu.cn").strip()
ATRUST_UIS_ENTITY_ID = os.environ.get("ATRUST_UIS_ENTITY_ID", "vpn").strip() or "vpn"
CAMPUS_ACCESS = os.environ.get("CAMPUS_ACCESS", "auto").strip().lower() or "auto"
UIS_2FA_MODE = os.environ.get("UIS_2FA_MODE", "qr").strip().lower() or "qr"
UIS_QR_OUTPUT = os.environ.get("UIS_QR_OUTPUT", "uis_qr_login.png").strip() or "uis_qr_login.png"
UIS_QR_TIMEOUT_SECONDS = int(os.environ.get("UIS_QR_TIMEOUT_SECONDS", "300"))
UIS_QR_POLL_INTERVAL_SECONDS = float(os.environ.get("UIS_QR_POLL_INTERVAL_SECONDS", "2"))

WEBVPN_AES_KEY = b"wrdvpnisthebest!"
WEBVPN_AES_IV = b"wrdvpnisthebest!"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)
