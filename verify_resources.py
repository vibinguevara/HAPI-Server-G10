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

# Disable SSL warnings/verification for localhost
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

BASE_URL = "https://localhost:8080"
REDIRECT_URI = "http://localhost:8080/"
CLIENT_ID = "my-client"
LOG_FILE_PATH = "src/main/resources/fhir-resources/response_log.txt"

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
    print("1. Generating PKCE...")
    code_verifier, code_challenge = generate_pkce()
    state = secrets.token_urlsafe(16)

    print("2. Requesting Authorization Code (Bypassing UI)...")
    consent_url = f"{BASE_URL}/auth/consent"
    
    # Needs scopes for reading Patient, Practitioner and others
    # patient/*.read user/*.read launch/patient
    
    params = {
        "decision": "allow",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "scope": "openid profile launch/patient patient/*.read user/*.read",
    }
    
    # We want "approved_scopes" to be repeated
    params_list = list(params.items())
    params_list.append(("approved_scopes", "openid"))
    params_list.append(("approved_scopes", "profile"))
    params_list.append(("approved_scopes", "launch/patient"))
    params_list.append(("approved_scopes", "patient/*.read"))
    params_list.append(("approved_scopes", "user/*.read"))
    
    data = urllib.parse.urlencode(params_list).encode('utf-8')
    
    print(f"   POST {consent_url}")
    
    req = urllib.request.Request(consent_url, data=data, method="POST")
    opener = urllib.request.build_opener(NoRedirectHandler)
    
    try:
        https_handler = urllib.request.HTTPSHandler(context=ctx)
        opener = urllib.request.build_opener(https_handler, NoRedirectHandler)
        
        with opener.open(req) as response:
            if response.code in [302, 303, 301, 307]:
                location = response.headers.get('Location')
                print(f"   Redirected to: {location}")
                
                match = re.search(r'code=([^&]+)', location)
                if match:
                    code = match.group(1)
                    print(f"   Authorization Code: {code}")
                else:
                    print("   Error: Could not find code in redirect URL")
                    return None
            else:
                print(f"   Error: Expected 302 Redirect, got {response.code}")
                try:
                    print(response.read().decode('utf-8'))
                except:
                    pass
                return None

    except urllib.error.HTTPError as e:
        print(f"   HTTP Error: {e.code} {e.reason}")
        try:
            print(e.read().decode('utf-8'))
        except:
            pass
        return None

    print("3. Exchanging Code for Access Token...")
    token_url = f"{BASE_URL}/auth/token"
    token_params = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "code_verifier": code_verifier
    }
    token_data = urllib.parse.urlencode(token_params).encode('utf-8')
    
    print(f"   POST {token_url}")
    req = urllib.request.Request(token_url, data=token_data, method="POST")
    
    try:
        with urllib.request.urlopen(req, context=ctx) as response:
            resp_body = response.read().decode('utf-8')
            token_json = json.loads(resp_body)
            access_token = token_json.get('access_token')
            print(f"   Access Token obtained successfully")
            return access_token
    except urllib.error.HTTPError as e:
        print(f"   HTTP Error: {e.code} {e.reason}")
        try:
            print(e.read().decode('utf-8'))
        except:
            pass
        return None

def fetch_and_log_resource(access_token, resource_path, log_file):
    url = f"{BASE_URL}/fhir/{resource_path}"
    print(f"Fetching {url}...")
    
    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {access_token}")
    
    try:
        with urllib.request.urlopen(req, context=ctx) as response:
            print(f"   Success! Status: {response.status}")
            body = response.read().decode('utf-8')
            
            # Format JSON for readability
            parsed_json = json.loads(body)
            formatted_json = json.dumps(parsed_json, indent=2)
            
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            with open(log_file, "a", encoding='utf-8') as f:
                f.write(f"\n--- RESOURCE: {resource_path} ---\n")
                f.write(formatted_json)
                f.write("\n")
                
    except urllib.error.HTTPError as e:
        print(f"   Error: {e.code} {e.reason}")
        try:
             print(e.read().decode('utf-8'))
        except:
            pass

if __name__ == "__main__":
    # Clear log file first
    if os.path.exists(LOG_FILE_PATH):
        os.remove(LOG_FILE_PATH)

    token = get_access_token()
    if token:
        # Patient ID patient-123
        fetch_and_log_resource(token, "Patient/patient-123", LOG_FILE_PATH)
        
        # Practitioner ID example
        fetch_and_log_resource(token, "Practitioner/example", LOG_FILE_PATH)
        
        # CapabilityStatement ID us-core-server
        fetch_and_log_resource(token, "CapabilityStatement/us-core-server", LOG_FILE_PATH)
