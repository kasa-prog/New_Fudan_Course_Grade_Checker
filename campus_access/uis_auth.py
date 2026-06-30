"""Shared Fudan UIS authentication helpers."""

import html as html_mod
import os
import re
import time
from urllib.parse import parse_qs, unquote, urljoin, urlparse

import base64
import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

from . import config

try:
    import pyotp
except ImportError:  # pragma: no cover - optional dependency
    pyotp = None


def _resolve_totp_secret() -> str:
    return os.environ.get("ATRUST_TOTP_SECRET", "").strip() or os.environ.get(
        "UIS_TOTP_SECRET", ""
    ).strip()


def _resolve_2fa_mode(module_codes: list[str]) -> str:
    mode = config.UIS_2FA_MODE
    if mode == "auto":
        if "qr" in module_codes:
            return "qr"
        if any(code in module_codes for code in ("userAndOtp", "userAndOA")):
            return "otp"
        return "qr"
    return mode


def _extract_login_token(execute_data: dict) -> str | None:
    login_token = execute_data.get("loginToken")
    data_field = execute_data.get("data")
    if not login_token and isinstance(data_field, dict):
        login_token = data_field.get("loginToken")
    if not login_token and isinstance(data_field, str):
        if data_field.startswith("http"):
            return html_mod.unescape(data_field.replace("&amp;", "&"))
        if data_field.strip():
            login_token = data_field.strip()
    return login_token or None


def _secondary_module_codes(execute_data: dict) -> list[str]:
    module_codes = execute_data.get("moduleCodes") or execute_data.get("moduleCode") or []
    if isinstance(module_codes, str):
        return [module_codes]
    return list(module_codes)


def _uis_auth_execute(
    session: requests.Session,
    *,
    referer: str,
    origin: str,
    payload: dict,
) -> dict:
    resp = session.post(
        f"{config.IDP_BASE}/idp/authn/authExecute",
        json=payload,
        headers={
            "Content-Type": "application/json",
            "Referer": referer,
            "Origin": origin,
        },
        timeout=30,
    )
    execute_data = resp.json()
    if str(execute_data.get("code")) != "200":
        raise RuntimeError(
            f"UIS authExecute failed: {execute_data.get('message') or execute_data}"
        )
    return execute_data


def _uis_get_second_auth_data(
    session: requests.Session,
    *,
    referer: str,
    params: dict,
) -> dict:
    resp = session.get(
        f"{config.IDP_BASE}/idp/authCenter/getSecondAuthData",
        params=params,
        headers={"Referer": referer, "Origin": config.IDP_BASE},
        timeout=30,
    )
    return resp.json()


def _find_qr_payload(data) -> str | None:
    if isinstance(data, str):
        text = data.strip()
        if text.startswith("data:image"):
            return text
        if text.startswith("http://") or text.startswith("https://"):
            return text
        if len(text) > 100 and re.fullmatch(r"[A-Za-z0-9+/=\r\n]+", text):
            return text
        return None

    if not isinstance(data, dict):
        return None

    for key in (
        "qrCode",
        "qrCodeBase64",
        "qrCodeUrl",
        "qrImg",
        "qrcode",
        "qrcodeUrl",
        "image",
        "img",
        "content",
        "url",
    ):
        found = _find_qr_payload(data.get(key))
        if found:
            return found
    return None


def _save_qr_image(session: requests.Session, qr_payload: str, output_path: str) -> str:
    if qr_payload.startswith("data:image"):
        _, encoded = qr_payload.split(",", 1)
        image_bytes = base64.b64decode(encoded)
    elif qr_payload.startswith("http://") or qr_payload.startswith("https://"):
        resp = session.get(qr_payload, timeout=30)
        resp.raise_for_status()
        image_bytes = resp.content
    else:
        image_bytes = base64.b64decode(qr_payload)

    with open(output_path, "wb") as handle:
        handle.write(image_bytes)
    return output_path


def _emit_qr_for_user(session: requests.Session, qr_payload: str) -> None:
    saved_path = _save_qr_image(session, qr_payload, config.UIS_QR_OUTPUT)
    print("[*] UIS secondary auth QR ready")
    print(f"[*] Open {saved_path} and scan with Fudan E账通 APP (E-account)")
    print("[*] Waiting for mobile scan confirmation...")


def _poll_qr_login_token(
    session: requests.Session,
    *,
    referer: str,
    origin: str,
    student_id: str,
    lck: str,
    entity_id: str,
    auth_chain_code: str,
    request_type: str,
    request_number,
) -> str:
    params = {
        "lck": lck,
        "entityId": entity_id,
        "authModuleCode": "qr",
        "authChainCode": auth_chain_code,
        "loginName": student_id,
    }
    if request_number is not None:
        params["requestNumber"] = request_number

    poll_payload = {
        "authModuleCode": "qr",
        "authChainCode": auth_chain_code,
        "entityId": entity_id,
        "requestType": request_type,
        "lck": lck,
        "authPara": {"loginName": student_id},
    }
    if request_number is not None:
        poll_payload["requestNumber"] = request_number

    deadline = time.time() + config.UIS_QR_TIMEOUT_SECONDS
    qr_saved = False
    last_message = ""

    while time.time() < deadline:
        for source_name, payload in (
            ("getSecondAuthData", params),
            ("authExecute", poll_payload),
        ):
            if source_name == "getSecondAuthData":
                data = _uis_get_second_auth_data(session, referer=referer, params=payload)
            else:
                try:
                    data = _uis_auth_execute(
                        session, referer=referer, origin=origin, payload=payload
                    )
                except RuntimeError as exc:
                    last_message = str(exc)
                    continue

            last_message = str(data.get("message") or data.get("code") or "")
            login_token = _extract_login_token(data)
            if isinstance(login_token, str) and login_token.startswith("http"):
                return login_token
            if login_token:
                print("[+] UIS QR secondary authentication completed")
                return login_token

            qr_payload = _find_qr_payload(data.get("data"))
            if qr_payload and not qr_saved:
                _emit_qr_for_user(session, qr_payload)
                qr_saved = True

        time.sleep(config.UIS_QR_POLL_INTERVAL_SECONDS)

    raise RuntimeError(
        "UIS QR secondary authentication timed out "
        f"after {config.UIS_QR_TIMEOUT_SECONDS}s (last={last_message or 'no QR payload'})"
    )


def _uis_followup_with_qr(
    session: requests.Session,
    *,
    referer: str,
    origin: str,
    student_id: str,
    lck: str,
    entity_id: str,
    auth_chain_code: str,
    request_type: str,
    execute_data: dict,
) -> str:
    modules = _secondary_module_codes(execute_data)
    if "qr" not in modules:
        raise RuntimeError(
            "UIS secondary QR authentication unavailable "
            f"(available={modules})"
        )

    chain_code = execute_data.get("authChainCode") or auth_chain_code
    request_number = execute_data.get("requestNumber")
    print("[*] UIS requires E账通 QR scan for secondary authentication")

    auth_para = {"loginName": student_id}
    select_payload = {
        "authModuleCode": "qr",
        "authChainCode": chain_code,
        "entityId": entity_id,
        "requestType": request_type,
        "lck": lck,
        "authPara": auth_para,
    }
    if request_number is not None:
        select_payload["requestNumber"] = request_number
    try:
        select_data = _uis_auth_execute(
            session, referer=referer, origin=origin, payload=select_payload
        )
        login_token = _extract_login_token(select_data)
        if isinstance(login_token, str) and login_token.startswith("http"):
            return login_token
        if login_token:
            return login_token
        qr_payload = _find_qr_payload(select_data.get("data"))
        if qr_payload:
            _emit_qr_for_user(session, qr_payload)
    except RuntimeError as exc:
        print(f"[*] UIS QR bootstrap via authExecute: {exc}")

    return _poll_qr_login_token(
        session,
        referer=referer,
        origin=origin,
        student_id=student_id,
        lck=lck,
        entity_id=entity_id,
        auth_chain_code=chain_code,
        request_type=request_type,
        request_number=request_number,
    )


def _uis_followup_with_otp(
    session: requests.Session,
    *,
    referer: str,
    origin: str,
    lck: str,
    entity_id: str,
    auth_chain_code: str,
    request_type: str,
    execute_data: dict,
) -> str:
    totp_secret = _resolve_totp_secret()
    if not totp_secret:
        modules = _secondary_module_codes(execute_data)
        raise RuntimeError(
            "UIS requires secondary authentication for aTrust OAuth "
            f"(module={modules}, message={execute_data.get('message')}). "
            "Bind third-party OTP in mail.fudan.edu.cn and set ATRUST_TOTP_SECRET."
        )
    if pyotp is None:
        raise RuntimeError("UIS OTP requires pyotp package")

    modules = _secondary_module_codes(execute_data)
    module_candidates = []
    for preferred in ("userAndOtp", "userAndOA"):
        if preferred in modules:
            module_candidates.append(preferred)
    if not module_candidates:
        module_candidates = ["userAndOtp", "userAndOA"]

    otp_code = pyotp.TOTP(totp_secret).now()
    chain_code = execute_data.get("authChainCode") or auth_chain_code
    field_candidates = ("dynamicPassword", "otpCode", "verifyCode", "token")

    last_error = ""
    for module_code in module_candidates:
        for field_name in field_candidates:
            payload = {
                "authModuleCode": module_code,
                "authChainCode": chain_code,
                "entityId": entity_id,
                "requestType": request_type,
                "lck": lck,
                "authPara": {field_name: otp_code},
            }
            try:
                otp_data = _uis_auth_execute(
                    session, referer=referer, origin=origin, payload=payload
                )
            except RuntimeError as exc:
                last_error = str(exc)
                continue

            login_token = _extract_login_token(otp_data)
            if isinstance(login_token, str) and login_token.startswith("http"):
                return login_token
            if login_token:
                print(f"[+] UIS secondary OTP accepted via {module_code}/{field_name}")
                return login_token
            last_error = (
                f"UIS OTP step returned no loginToken "
                f"(module={module_code}, field={field_name}, "
                f"message={otp_data.get('message')})"
            )

    raise RuntimeError(
        "UIS secondary OTP authentication failed "
        f"(available={modules}, last={last_error or 'unknown'})"
    )


def _uis_followup_secondary(
    session: requests.Session,
    *,
    referer: str,
    origin: str,
    student_id: str,
    lck: str,
    entity_id: str,
    auth_chain_code: str,
    request_type: str,
    execute_data: dict,
) -> str:
    module_codes = _secondary_module_codes(execute_data)
    mode = _resolve_2fa_mode(module_codes)

    if mode == "qr":
        return _uis_followup_with_qr(
            session,
            referer=referer,
            origin=origin,
            student_id=student_id,
            lck=lck,
            entity_id=entity_id,
            auth_chain_code=auth_chain_code,
            request_type=request_type,
            execute_data=execute_data,
        )
    if mode == "otp":
        return _uis_followup_with_otp(
            session,
            referer=referer,
            origin=origin,
            lck=lck,
            entity_id=entity_id,
            auth_chain_code=auth_chain_code,
            request_type=request_type,
            execute_data=execute_data,
        )
    raise RuntimeError(
        f"Unsupported UIS_2FA_MODE={mode!r}; use qr, otp, or auto"
    )


def extract_auth_params_from_url(url):
    if not url:
        return None, None

    url = html_mod.unescape(url)
    parsed = urlparse(url)
    query_strings = [parsed.query]
    if parsed.fragment:
        query_strings.append(
            parsed.fragment.split("?", 1)[1] if "?" in parsed.fragment else parsed.fragment
        )

    for query_string in query_strings:
        query = parse_qs(query_string, keep_blank_values=True)
        lck = query.get("lck", [None])[0]
        entity_id = query.get("entityId", [None])[0]
        if lck and entity_id:
            return lck, unquote(entity_id)

    match_lck = re.search(r"(?:[?&#]|^)lck=([^&#]+)", url)
    match_entity_id = re.search(r"(?:[?&#]|^)entityId=([^&#]+)", url)
    if match_lck and match_entity_id:
        return match_lck.group(1), unquote(match_entity_id.group(1))

    return None, None


def extract_auth_params_from_response(response):
    candidate_urls = [response.url]
    for redirect_response in response.history:
        candidate_urls.append(redirect_response.url)
        location = redirect_response.headers.get("Location")
        if location:
            candidate_urls.append(location)
            candidate_urls.append(urljoin(redirect_response.url, location))

    for candidate_url in candidate_urls:
        lck, entity_id = extract_auth_params_from_url(candidate_url)
        if lck and entity_id:
            return lck, entity_id

    page_text = html_mod.unescape(response.text or "")
    match_lck = re.search(r"(?:[?&#]|^)lck=([^&#\"'\s]+)", page_text)
    match_entity_id = re.search(r"(?:[?&#]|^)entityId=([^&#\"'\s]+)", page_text)
    if match_lck and match_entity_id:
        return match_lck.group(1), unquote(match_entity_id.group(1))

    return None, None


def encrypt_password(password: str, pub_key_b64: str) -> str:
    pem = (
        "-----BEGIN PUBLIC KEY-----\n"
        + pub_key_b64
        + "\n-----END PUBLIC KEY-----"
    )
    rsa_key = RSA.import_key(pem)
    cipher = PKCS1_v1_5.new(rsa_key)
    encrypted = cipher.encrypt(password.encode("utf-8"))
    return base64.b64encode(encrypted).decode("ascii")


def uis_password_login(
    session: requests.Session,
    student_id: str,
    password: str,
    lck: str,
    entity_id: str,
    origin: str | None = None,
) -> str:
    """Run UIS username/password auth and return the post-login redirect URL."""
    origin = origin or config.IDP_BASE
    referer = f"{config.IDP_BASE}/ac/#/index?lck={lck}&entityId={requests.utils.quote(entity_id, safe='')}"

    resp = session.post(
        f"{config.IDP_BASE}/idp/authn/queryAuthMethods",
        json={"lck": lck, "entityId": entity_id},
        headers={
            "Content-Type": "application/json",
            "Referer": referer,
            "Origin": origin,
        },
        timeout=30,
    )
    query_data = resp.json()
    auth_chain_code = ""
    for method in query_data.get("data", []):
        if method.get("moduleCode") == "userAndPwd":
            auth_chain_code = method.get("authChainCode", "")
            break
    if not auth_chain_code:
        raise RuntimeError("UIS queryAuthMethods did not return userAndPwd chain")

    resp = session.post(
        f"{config.IDP_BASE}/idp/authn/getJsPublicKey",
        headers={"Referer": referer},
        timeout=30,
    )
    pub_key_b64 = resp.json().get("data", "")
    if not pub_key_b64:
        raise RuntimeError("UIS getJsPublicKey returned empty key")

    encrypted_password = encrypt_password(password, pub_key_b64)
    execute_data = _uis_auth_execute(
        session,
        referer=referer,
        origin=origin,
        payload={
            "authModuleCode": "userAndPwd",
            "authChainCode": auth_chain_code,
            "entityId": entity_id,
            "requestType": query_data.get("requestType", "chain_type"),
            "lck": lck,
            "authPara": {
                "loginName": student_id,
                "password": encrypted_password,
                "verifyCode": "",
            },
        },
    )

    login_token = _extract_login_token(execute_data)
    if isinstance(login_token, str) and login_token.startswith("http"):
        return login_token

    if not login_token:
        module_codes = _secondary_module_codes(execute_data)
        if execute_data.get("second") or module_codes:
            login_token = _uis_followup_secondary(
                session,
                referer=referer,
                origin=origin,
                student_id=student_id,
                lck=lck,
                entity_id=entity_id,
                auth_chain_code=auth_chain_code,
                request_type=query_data.get("requestType", "chain_type"),
                execute_data=execute_data,
            )
        else:
            raise RuntimeError(
                "UIS authExecute returned no loginToken "
                f"(message={execute_data.get('message')}, moduleCode={execute_data.get('moduleCode')})"
            )

    resp = session.post(
        f"{config.IDP_BASE}/idp/authCenter/authnEngine",
        data={"loginToken": login_token},
        headers={"Referer": referer, "Origin": origin},
        timeout=30,
    )
    match = re.search(r'locationValue\s*=\s*"([^"]+)"', resp.text)
    if not match:
        match = re.search(r'(https?://[^\s"\'<>]+)', resp.text)
    if not match:
        raise RuntimeError("UIS authnEngine did not return redirect URL")
    return html_mod.unescape(match.group(1).replace("&amp;", "&"))
