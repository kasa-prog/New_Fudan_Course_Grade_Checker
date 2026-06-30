import os

WEBVPN_BASE = "https://webvpn.fudan.edu.cn"
IDP_BASE = "https://id.fudan.edu.cn"
GRADE_BASE = "https://fdjwgl.fudan.edu.cn"
GRADE_TARGET = f"{GRADE_BASE}/student/for-std/grade/sheet/"

ATRUST_PORTAL = os.environ.get("ATRUST_PORTAL", "").strip().rstrip("/")
CAMPUS_ACCESS = os.environ.get("CAMPUS_ACCESS", "auto").strip().lower() or "auto"

WEBVPN_AES_KEY = b"wrdvpnisthebest!"
WEBVPN_AES_IV = b"wrdvpnisthebest!"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)
