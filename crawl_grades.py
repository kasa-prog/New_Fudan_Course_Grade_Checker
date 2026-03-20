import requests
import re
import os
import sys
import time
import json
import base64
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from cryptography.fernet import Fernet

"""
Fudan University Grade Crawler
Target Page: https://fdjwgl.fudan.edu.cn/student/for-std/grade/sheet/
API Endpoint: https://fdjwgl.fudan.edu.cn/student/for-std/grade/sheet/info/{grade_sheet_id}
Course Info API: https://fdjwgl.fudan.edu.cn/student/for-std/lesson-search/semester/{semester_id}/search/{grade_sheet_id}?courseCodeLike={course_code}&courseNameZhLike={course_name}&queryPage__=1%2C20

Authentication:
- Student ID and Password from environment variables StuId and UISPsw.
- Uses Fudan UIS (Unified Identity Service) with RSA encryption.
- Handles complex redirection chain and JS-based redirection.

Features:
- Dynamically detects student grade sheet ID.
- Fetches grades for all semesters, including course credits.
- Calculates GPA per semester and cumulative GPA.
- Saves grades to an encrypted JSON file (`grades_encrypted.json`).
- Compares current grades with previously stored grades.
- Sends email notification if new grades are released or GPA changes (Good/Bad News).
- Designed to run in GitHub Actions workflow.
"""

# --- Configuration ---
GRADES_FILE = "grades_encrypted.json"
DEFAULT_SMTP_PORT = 465  # SSL port


def get_sender_email():
    return os.environ.get("EMAIL_SENDER") or os.environ.get("QQ_EMAIL_SENDER", "")


def get_smtp_auth_code():
    return os.environ.get("SMTP_AUTH_CODE") or os.environ.get("QQ_SMTP", "")


def resolve_smtp_config(sender_email):
    domain = (sender_email or "").split("@")[-1].lower()
    if domain == "gmail.com":
        return "smtp.gmail.com", DEFAULT_SMTP_PORT
    if domain == "qq.com":
        return "smtp.qq.com", DEFAULT_SMTP_PORT
    raise ValueError(f"Unsupported sender email domain for SMTP auto config: {domain}")


def get_encryption_key():
    """Generates a Fernet key from 4 environment variables to prevent collision."""
    stu_id = os.environ.get("StuId", "")
    password = os.environ.get("UISPsw", "")
    sender = get_sender_email()
    smtp = get_smtp_auth_code()
    
    # Combine variables with separators to ensure uniqueness
    raw_key = f"{stu_id}|{password}|{sender}|{smtp}"
    
    # Use SHA256 hash to derive a 32-byte key for Fernet
    import hashlib
    key = base64.urlsafe_b64encode(hashlib.sha256(raw_key.encode('utf-8')).digest())
    return key

def encrypt_data(data, key):
    """Encrypts data using Fernet symmetric encryption."""
    f = Fernet(key)
    return f.encrypt(json.dumps(data, ensure_ascii=False).encode('utf-8'))

def decrypt_data(encrypted_data, key):
    """Decrypts data using Fernet symmetric encryption."""
    f = Fernet(key)
    return json.loads(f.decrypt(encrypted_data).decode('utf-8'))

def encrypt_password(password, public_key_b64):
    """Encrypt password using RSA PKCS1_v1_5 as used by JSEncrypt."""
    key_der = base64.b64decode(public_key_b64)
    public_key = RSA.import_key(key_der)
    cipher = PKCS1_v1_5.new(public_key)
    encrypted_pw = cipher.encrypt(password.encode('utf-8'))
    return base64.b64encode(encrypted_pw).decode('utf-8')

def send_email(subject, body, recipient_email, sender_email, smtp_auth_code):
    """Sends an email notification."""
    if not sender_email or not smtp_auth_code:
        print(f"[-] Error: Sender email and SMTP auth code must be provided for email notification.")
        return

    message = MIMEText(body, 'plain', 'utf-8')
    message['From'] = Header(f"Fudan Grade Monitor <{sender_email}>")
    message['To'] = Header(recipient_email)
    message['Subject'] = Header(subject)

    try:
        smtp_server, smtp_port = resolve_smtp_config(sender_email)
        smtp_obj = smtplib.SMTP_SSL(smtp_server, smtp_port)
        smtp_obj.login(sender_email, smtp_auth_code)
        smtp_obj.sendmail(sender_email, recipient_email, message.as_string())
        smtp_obj.quit()
        print(f"[+] Email notification sent to {recipient_email} via {smtp_server}")
    except Exception as e:
        print(f"[-] Error sending email: {e}")

def get_course_credits(session, semester_id, grade_sheet_id, course_code, course_name):
    """Fetches course credits using the new course info API."""
    # The API expects Chinese characters in courseNameZhLike to be URL-encoded
    course_name_encoded = requests.utils.quote(course_name)
    course_info_api = f"https://fdjwgl.fudan.edu.cn/student/for-std/lesson-search/semester/{semester_id}/search/{grade_sheet_id}?courseCodeLike={course_code}&courseNameZhLike={course_name_encoded}&queryPage__=1%2C20"
    
    try:
        res = session.get(course_info_api)
        data = res.json()
        if data and data.get('data'):
            # The API returns a list of courses, pick the first one matching the code
            for course_entry in data['data']:
                if course_entry.get('course') and course_entry['course'].get('code') == course_code:
                    return course_entry['course'].get('credits')
        # Fallback if specific course not found by code, try by name
        if data and data.get('data'):
            for course_entry in data['data']:
                if course_entry.get('course') and course_entry['course'].get('nameZh') == course_name:
                    return course_entry['course'].get('credits')
    except Exception as e:
        # print(f"[-] Error fetching credits for {course_name} ({course_code}): {e}")
        pass # Suppress error for not finding credits, it might not exist for some courses
    return None # Return None if credits not found

def calculate_gpa(grades_data_map):
    """Calculates cumulative GPA from grades data."""
    total_gp_x_credits = 0.0
    total_credits = 0.0

    for semester_grades in grades_data_map.values():
        for grade_entry in semester_grades:
            gp = grade_entry.get('gp')
            credits = grade_entry.get('credits')
            grade = grade_entry.get('gaGrade')

            # Exclude P/NP grades from GPA calculation
            if grade in ['P', 'NP']:
                continue

            if gp is not None and credits is not None and credits > 0:
                total_gp_x_credits += float(gp) * float(credits)
                total_credits += float(credits)
    
    if total_credits > 0:
        return round(total_gp_x_credits / total_credits, 3)
    return 0.0

def crawl_grades():
    stu_id = os.environ.get('StuId')
    password = os.environ.get('UISPsw') # UISPsw will also be used as encryption key

    if not stu_id or not password:
        print("[-] Error: Environment variables StuId and UISPsw must be set.")
        sys.exit(1)

    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    })

    # Step 1: Access target page to trigger redirection to UIS
    target_url = "https://fdjwgl.fudan.edu.cn/student/for-std/grade/sheet/"
    print(f"[*] Accessing {target_url}...")
    try:
        res = session.get(target_url, allow_redirects=True)
    except Exception as e:
        raise Exception(f"[-] Network error: {e}")
    
    # Extract lck and entityId from the UIS login URL
    lck = None
    match_lck = re.search(r'lck=([^&]+)', res.url)
    if match_lck:
        lck = match_lck.group(1)
    
    entityId = None
    match_eid = re.search(r'entityId=([^&]+)', res.url)
    if match_eid:
        entityId = requests.utils.unquote(match_eid.group(1))

    if not lck or not entityId:
        raise Exception("[-] Failed to get authentication parameters from redirect URL.")

    # Step 2: Query authentication methods to get authChainCode
    print("[*] Querying authentication methods...")
    query_url = "https://id.fudan.edu.cn/idp/authn/queryAuthMethods"
    try:
        res_query = session.post(query_url, json={"lck": lck, "entityId": entityId})
        query_data = res_query.json()
        auth_chain_code = query_data['data'][0]['authChainCode']
        request_type = query_data['requestType']
    except Exception as e:
        raise Exception(f"[-] Failed to query auth methods: {e}")

    # Step 3: Get RSA public key for password encryption
    print("[*] Retrieving RSA public key...")
    pub_key_url = "https://id.fudan.edu.cn/idp/authn/getJsPublicKey"
    try:
        res_pub = session.post(pub_key_url)
        pub_key = res_pub.json()['data']
    except Exception as e:
        raise Exception(f"[-] Failed to get public key: {e}")

    # Step 4: Encrypt password
    encrypted_password_uis = encrypt_password(password, pub_key)

    # Step 5: Execute authentication
    print("[*] Authenticating...")
    execute_url = "https://id.fudan.edu.cn/idp/authn/authExecute"
    payload = {
        "authModuleCode": "userAndPwd",
        "authChainCode": auth_chain_code,
        "entityId": entityId,
        "requestType": request_type,
        "lck": lck,
        "authPara": {
            "loginName": stu_id,
            "password": encrypted_password_uis,
            "verifyCode": ""
        }
    }
    try:
        res_execute = session.post(execute_url, json=payload)
        execute_data = res_execute.json()
    except Exception as e:
        raise Exception(f"[-] Authentication request failed: {e}")

    if execute_data.get('code') != 200 and execute_data.get('code') != "200":
        raise Exception(f"[-] Authentication failed: {execute_data.get('message')}")

    login_token = execute_data['loginToken']

    # Step 6: Submit loginToken to authnEngine and handle JS redirect
    print("[*] Finalizing session...")
    engine_url = "https://id.fudan.edu.cn/idp/authCenter/authnEngine"
    try:
        res_engine = session.post(engine_url, data={"loginToken": login_token})
        
        # Extract locationValue from JS redirect script
        match_loc = re.search(r'var locationValue = "([^"]+)"', res_engine.text)
        if not match_loc:
            raise Exception("[-] Failed to find redirection link in authentication engine response.")
        
        redirect_url = match_loc.group(1).replace('&amp;', '&')
        # Visit the redirect URL to set cookies for the student system
        res_final = session.get(redirect_url, allow_redirects=True)
        print(f"[+] Login final redirection: {res_final.url}")
    except Exception as e:
        raise Exception(f"[-] Session finalization failed: {e}")

    # Add a short delay to ensure the session is fully established on the server side
    time.sleep(1)

    # Step 7: Dynamically find the grade sheet ID
    grade_base_url = "https://fdjwgl.fudan.edu.cn/student/for-std/grade/sheet/"
    print("[*] Detecting student grade sheet ID...")
    try:
        res_detect = session.get(grade_base_url, allow_redirects=True)
        match_id = re.search(r'semester-index/(\d+)', res_detect.url)
        if not match_id:
            raise Exception(f"[-] Failed to detect grade sheet ID. Final URL was: {res_detect.url}")
        else:
            grade_sheet_id = match_id.group(1)
            print(f"[+] Detected grade sheet ID")
    except Exception as e:
        raise Exception(f"[-] Error detecting grade sheet ID: {e}")

    # Step 8: Fetch grades from API
    grade_api = f"https://fdjwgl.fudan.edu.cn/student/for-std/grade/sheet/info/{grade_sheet_id}"
    print(f"[*] Fetching all grades...")
    try:
        res_grades = session.get(grade_api)
        if res_grades.status_code == 200:
            grades_data = res_grades.json()
            
            # Step 9: Fetch credits for each course
            print("[*] Fetching course credits...")
            all_grades_with_credits = {}
            for semester_id_str, semester_grades in grades_data['semesterId2studentGrades'].items():
                semester_id = int(semester_id_str)
                all_grades_with_credits[semester_id_str] = []
                for grade_entry in semester_grades:
                    course_code = grade_entry.get('courseCode')
                    course_name = grade_entry.get('courseName')
                    if course_code and course_name:
                        credits = get_course_credits(session, semester_id, grade_sheet_id, course_code, course_name)
                        grade_entry['credits'] = credits
                    else:
                        grade_entry['credits'] = None
                    all_grades_with_credits[semester_id_str].append(grade_entry)
            grades_data['semesterId2studentGrades'] = all_grades_with_credits

            print("[+] Grades and credits fetched successfully!")
            return grades_data
        else:
            raise Exception(f"[-] Failed to fetch grades. Status code: {res_grades.status_code}")
    except Exception as e:
        raise Exception(f"[-] Error fetching grades: {e}")
    return None

def compare_and_notify(new_grades_data):
    """Compares new grades with old, calculates GPA, and sends notifications."""
    sender_email = get_sender_email()
    stu_id = os.environ.get("StuId")
    recipient_email = f"{stu_id}@m.fudan.edu.cn" if stu_id else None
    smtp_auth_code = get_smtp_auth_code()

    # UISPsw is needed for key generation implicitly by get_encryption_key
    # We check required vars for email and basic logic here
    if not smtp_auth_code:
        print(f"[-] Error: SMTP_AUTH_CODE (or QQ_SMTP) environment variable must be set for email notification.")
        return
    if not sender_email:
        print("[-] Error: EMAIL_SENDER (or QQ_EMAIL_SENDER) environment variable must be set.")
        return
    if not stu_id:
        print("[-] Error: StuId environment variable must be set to determine recipient email.")
        return

    key = get_encryption_key()

    old_grades_data = {}
    if os.path.exists(GRADES_FILE):
        print(f"[*] Loading old grades from {GRADES_FILE}...")
        try:
            with open(GRADES_FILE, "rb") as f:
                encrypted_old_grades = f.read()
            old_grades_data = decrypt_data(encrypted_old_grades, key)
        except Exception as e:
            print(f"[-] Error decrypting old grades: {e}. Starting fresh.")
            old_grades_data = {}
    else:
        print("[*] No existing grades file found. This is the first run.")

    # Calculate current and old GPA
    current_gpa = calculate_gpa(new_grades_data['semesterId2studentGrades'])
    old_gpa = calculate_gpa(old_grades_data.get('semesterId2studentGrades', {}))

    # Identify new grades
    new_grades_found = []
    
    # Flatten old grades for easier lookup (courseCode -> grade_entry)
    old_grades_flat = {}
    for semester_grades in old_grades_data.get('semesterId2studentGrades', {}).values():
        for grade_entry in semester_grades:
            old_grades_flat[grade_entry['courseCode']] = grade_entry
    
    for semester_id, new_semester_grades in new_grades_data['semesterId2studentGrades'].items():
        for new_grade_entry in new_semester_grades:
            course_code = new_grade_entry['courseCode']
            old_grade_entry = old_grades_flat.get(course_code)

            if old_grade_entry is None:
                new_grades_found.append({
                    "courseName": new_grade_entry['courseName'],
                    "gaGrade": new_grade_entry['gaGrade'],
                    "gp": new_grade_entry['gp'],
                    "changeType": "new"
                })
            elif old_grade_entry.get('gaGrade') != new_grade_entry.get('gaGrade') or old_grade_entry.get('gp') != new_grade_entry.get('gp'):
                 new_grades_found.append({
                    "courseName": new_grade_entry['courseName'],
                    "old_gaGrade": old_grade_entry.get('gaGrade'),
                    "new_gaGrade": new_grade_entry['gaGrade'],
                    "old_gp": old_grade_entry.get('gp'),
                    "new_gp": new_grade_entry['gp'],
                    "changeType": "updated"
                })

    # Prepare email notification if changes found
    if new_grades_found:
        print("[+] New or updated grades found! Preparing email notification.")
        subject_prefix = "【自动推送】"
        if current_gpa > old_gpa:
            subject_prefix += "好消息！"
        elif current_gpa < old_gpa:
            subject_prefix += "坏消息！"
        else:
            subject_prefix += "成绩更新！"
        
        email_body = f"亲爱的同学：\n\n您的复旦大学成绩有新的更新：\n\n"
        for grade_change in new_grades_found:
            if grade_change['changeType'] == "new":
                email_body += f"课程：{grade_change['courseName']} 出分了！\n"
                email_body += f"  等级：{grade_change['gaGrade']}\n"
                email_body += f"  绩点：{grade_change['gp'] if grade_change['gp'] is not None else '-'}\n"
            elif grade_change['changeType'] == "updated":
                email_body += f"课程：{grade_change['courseName']} 成绩更新了！\n"
                email_body += f"  原有等级：{grade_change['old_gaGrade'] if grade_change['old_gaGrade'] is not None else '-'}\n"
                email_body += f"  新等级：{grade_change['new_gaGrade']}\n"
                email_body += f"  原有绩点：{grade_change['old_gp'] if grade_change['old_gp'] is not None else '-'}\n"
                email_body += f"  新绩点：{grade_change['new_gp'] if grade_change['new_gp'] is not None else '-'}\n"
            email_body += "\n"
        
        email_body += f"您当前的累计GPA为：{current_gpa:.3f}\n"
        if old_gpa > 0:
            email_body += f"您上次的累计GPA为：{old_gpa:.3f}\n"
        if current_gpa != old_gpa:
            email_body += f"GPA变化：{'↑' if current_gpa > old_gpa else '↓'}{abs(current_gpa - old_gpa):.3f}\n"

        send_email(subject_prefix + f"{'/'.join([g['courseName'] for g in new_grades_found])}课程出分了！", email_body, recipient_email, sender_email, smtp_auth_code)
    else:
        print("[*] No new or updated grades found.")

    # Save new grades (encrypted)
    encrypted_new_grades = encrypt_data(new_grades_data, key)
    with open(GRADES_FILE, "wb") as f:
        f.write(encrypted_new_grades)
    print(f"[+] New grades (encrypted) saved to {GRADES_FILE}")

def format_grades(data):
    """Helper to display grades in a readable format and print GPA."""
    semesters_list = data.get('semesters', [])
    grades_map = data.get('semesterId2studentGrades', {})
    
    all_gpa = calculate_gpa(grades_map)

    print(f"--- Cumulative GPA: {all_gpa:.3f} ---\n")

    for semester in semesters_list:
        s_id = str(semester['id'])
        s_name = semester['nameZh']
        print(f"=== {s_name} ===")
        semester_grades = grades_map.get(s_id, [])
        
        semester_total_gp_x_credits = 0.0
        semester_total_credits = 0.0

        if not semester_grades:
            print("  (No grades recorded)")
        else:
            print(f"{ 'Course Code':<12} { 'Course Name':<30} { 'Grade':<6} { 'GP':<5} { 'Credits':<7}")
            print("-" * 70)
            for g in semester_grades:
                code = g.get('courseCode', '-')
                name = g.get('courseName', '-')
                grade = g.get('gaGrade', '-')
                gp = g.get('gp')
                credits = g.get('credits')

                if gp is None: gp_display = '-'
                else: gp_display = f"{gp:.3f}"
                if credits is None: credits_display = '-'
                else: credits_display = f"{credits:.1f}"

                # Exclude P/NP from calculation
                if grade not in ['P', 'NP'] and gp is not None and credits is not None and credits > 0:
                    semester_total_gp_x_credits += float(gp) * float(credits)
                    semester_total_credits += float(credits)

                # Handle Chinese characters in alignment (approximate)
                print(f"{code:<12} {name[:25]:<30} {grade:<6} {gp_display:<5} {credits_display:<7}")
        
        semester_gpa = 0.0
        if semester_total_credits > 0:
            semester_gpa = round(semester_total_gp_x_credits / semester_total_credits, 3)
        print(f"  Semester GPA: {semester_gpa:.3f}")
        print()

def main():
    # UISPsw is still needed for login
    uis_password = os.environ.get('UISPsw')
    if not uis_password:
        print("[-] Error: UISPsw environment variable must be set.")
        sys.exit(1)

    new_grades_data = crawl_grades()
    if new_grades_data:
        # format_grades(new_grades_data)
        compare_and_notify(new_grades_data)

if __name__ == "__main__":
    main()