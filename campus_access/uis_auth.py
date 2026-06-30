"""Shared Fudan UIS authentication helpers."""

import html as html_mod
import re
from urllib.parse import parse_qs, unquote, urljoin, urlparse

import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import base64

from . import config


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
    resp = session.post(
        f"{config.IDP_BASE}/idp/authn/authExecute",
        json={
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

    login_token = execute_data.get("loginToken") or (execute_data.get("data") or {}).get(
        "loginToken"
    )
    if not login_token:
        raise RuntimeError(
            "UIS authExecute returned no loginToken "
            f"(keys={sorted(execute_data.keys())})"
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
