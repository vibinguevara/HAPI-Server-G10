
import urllib.request
import urllib.parse
import urllib.error
import json
import base64
import hashlib
import secrets
import ssl
import re
import os
from datetime import datetime

# Configuration
BASE_URL = "https://localhost:8080"
REDIRECT_URI = "http://localhost:8080/"
CLIENT_ID = "my-client"
BUNDLE_FILE_PATH = r"src\main\resources\fhir-resources\singlePatientInfernoG10.json"
DTO_LOG_FILE_PATH = r"src\main\resources\fhir-resources\response_log.txt"

# SSL Context
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        return fp
    http_error_301 = http_error_303 = http_error_307 = http_error_302

def generate_pkce():
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = hashlib.sha256(code_verifier.encode('ascii')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode('ascii').rstrip('=')
    return code_verifier, code_challenge

def get_access_token():
    print("Getting access token...")
    code_verifier, code_challenge = generate_pkce()
    state = secrets.token_urlsafe(16)

    consent_url = f"{BASE_URL}/auth/consent"
    params = {
        "decision": "allow",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "scope": "openid profile launch/patient user/*.write",
    }
    
    params_list = list(params.items())
    params_list.append(("approved_scopes", "openid"))
    params_list.append(("approved_scopes", "profile"))
    params_list.append(("approved_scopes", "launch/patient"))
    params_list.append(("approved_scopes", "user/*.write"))
    
    data = urllib.parse.urlencode(params_list).encode('utf-8')
    
    
    req = urllib.request.Request(consent_url, data=data, method="POST")
    
    # HTTPSHandler needed to use custom SSL context with opener
    https_handler = urllib.request.HTTPSHandler(context=ctx)
    opener = urllib.request.build_opener(https_handler, NoRedirectHandler)

    try:
        with opener.open(req) as response:
            if response.code in [302, 303, 301, 307]:
                location = response.headers.get('Location')
                match = re.search(r'code=([^&]+)', location)
                if match:
                    code = match.group(1)
                else:
                    print("Error: Could not find code in redirect URL")
                    return None
            else:
                print(f"Error: Expected redirect, got {response.code}")
                return None
    except urllib.error.HTTPError as e:
        print(f"HTTP Error during consent: {e.code} {e.reason}")
        return None

    token_url = f"{BASE_URL}/auth/token"
    token_params = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "code_verifier": code_verifier
    }
    token_data = urllib.parse.urlencode(token_params).encode('utf-8')
    
    req = urllib.request.Request(token_url, data=token_data, method="POST")
    try:
        with urllib.request.urlopen(req, context=ctx) as response:
            resp_body = response.read().decode('utf-8')
            token_json = json.loads(resp_body)
            return token_json.get('access_token')
    except Exception as e:
        print(f"Error getting token: {e}")
        return None

def import_bundle(token):
    print(f"Reading bundle from {BUNDLE_FILE_PATH}...")
    try:
        with open(BUNDLE_FILE_PATH, 'r', encoding='utf-8') as f:
            bundle_data = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    fhir_url = f"{BASE_URL}/fhir"
    print(f"Posting to {fhir_url}...")
    
    req = urllib.request.Request(fhir_url, data=bundle_data.encode('utf-8'), method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/fhir+json")
    
    log_entry = f"\n\n--- Import Attempt {datetime.now()} ---\n"
    
    try:
        with urllib.request.urlopen(req, context=ctx) as response:
            status = response.status
            body = response.read().decode('utf-8')
            print(f"Success! Status: {status}")
            log_entry += f"Status: {status}\nResponse:\n{body}\n"
            
    except urllib.error.HTTPError as e:
        print(f"HTTP Error: {e.code} {e.reason}")
        error_body = e.read().decode('utf-8')
        log_entry += f"Status: {e.code} {e.reason}\nError Body:\n{error_body}\n"
    except Exception as e:
        print(f"Exception: {e}")
        log_entry += f"Exception: {str(e)}\n"
        
    try:
        with open(DTO_LOG_FILE_PATH, "a", encoding='utf-8') as log_file:
            log_file.write(log_entry)
        print(f"Response appended to {DTO_LOG_FILE_PATH}")
    except Exception as e:
        print(f"Error writing log: {e}")

if __name__ == "__main__":
    token = get_access_token()
    if token:
        import_bundle(token)
    else:
        print("Could not retrieve token.")
