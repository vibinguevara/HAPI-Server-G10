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
import glob
from datetime import datetime

# Disable SSL warnings/verification for localhost
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

BASE_URL = "https://localhost:8080"
REDIRECT_URI = "http://localhost:8080/"
CLIENT_ID = "my-client"

RESOURCE_BASE_DIR = "src/main/resources/fhir-resources"
EXAMPLES_DIR = os.path.join(RESOURCE_BASE_DIR, "example")
RESPONSE_LOG_PATH = os.path.join(RESOURCE_BASE_DIR, "response_log.txt")

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
    
    # Requesting wide scope access
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
    
    print(f"   POST {consent_url}")
    
    req = urllib.request.Request(consent_url, data=data, method="POST")
    opener = urllib.request.build_opener(NoRedirectHandler)
    
    try:
        https_handler = urllib.request.HTTPSHandler(context=ctx)
        opener = urllib.request.build_opener(https_handler, NoRedirectHandler)
        
        with opener.open(req) as response:
            if response.code in [302, 303, 301, 307]:
                location = response.headers.get('Location')
                # print(f"   Redirected to: {location}")
                
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
    
    # print(f"   POST {token_url}")
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
        print(e.read().decode('utf-8'))
        return None

def log_response(file_name, status, response_body):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] File: {file_name} | Status: {status}\nResponse: {response_body}\n{'-'*80}\n"
    print(f"Logged {file_name}: {status}")
    try:
        with open(RESPONSE_LOG_PATH, "a", encoding='utf-8') as log_file:
            log_file.write(log_entry)
    except Exception as e:
        print(f"Error writing to log file: {e}")

def import_resource(access_token, file_path):
    file_name = os.path.basename(file_path)
    # print(f"Importing {file_name}...")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            resource_data = json.load(f)
    except Exception as e:
        log_response(file_name, "FAILURE", f"File read error: {str(e)}")
        return

    resource_type = resource_data.get("resourceType")
    if not resource_type:
        log_response(file_name, "FAILURE", "Missing resourceType in JSON")
        return

    # Check ID for PUT vs POST
    resource_id = resource_data.get("id")
    
    if resource_id:
        fhir_url = f"{BASE_URL}/fhir/{resource_type}/{resource_id}"
        method = "PUT"
    else:
        fhir_url = f"{BASE_URL}/fhir/{resource_type}"
        method = "POST"
    
    json_body = json.dumps(resource_data).encode('utf-8')
    
    req = urllib.request.Request(fhir_url, data=json_body, method=method)
    req.add_header("Authorization", f"Bearer {access_token}")
    req.add_header("Content-Type", "application/fhir+json")
    
    try:
        with urllib.request.urlopen(req, context=ctx) as response:
            resp_body = response.read().decode('utf-8')
            log_response(file_name, f"SUCCESS ({response.status})", resp_body)
            
    except urllib.error.HTTPError as e:
        try:
            resp_body = e.read().decode('utf-8')
        except:
            resp_body = "No response body"
        log_response(file_name, f"FAILURE ({e.code})", resp_body)
    except Exception as e:
        log_response(file_name, "FAILURE", f"Exception: {str(e)}")

def get_sorted_files(directory):
    if not os.path.exists(directory):
        print(f"Directory not found: {directory}")
        return []

    all_files = glob.glob(os.path.join(directory, "*.json"))
    
    patient_files = []
    encounter_files = []
    practitioner_files = []
    other_files = []

    for f in all_files:
        filename = os.path.basename(f)
        if filename.startswith("Patient"):
            patient_files.append(f)
        elif filename.startswith("Encounter"):
            encounter_files.append(f)
        elif filename.startswith("Practitioner"):
            practitioner_files.append(f)
        else:
            other_files.append(f)
    
    # Sort specifically by name within groups if needed, though glob order is usually system dependent
    patient_files.sort()
    encounter_files.sort()
    practitioner_files.sort()
    other_files.sort()

    return patient_files + encounter_files + practitioner_files + other_files

if __name__ == "__main__":
    print("Starting FHIR Resource Import Process...")
    
    # Initialize log file
    with open(RESPONSE_LOG_PATH, "a", encoding='utf-8') as f:
        f.write(f"\n{'='*80}\nNEW IMPORT SESSION: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n{'='*80}\n")

    token = get_access_token()
    
    if not token:
        print("Failed to obtain access token. Aborting.")
        exit(1)
        
    sorted_files = get_sorted_files(EXAMPLES_DIR)
    
    if not sorted_files:
        print("No files to import.")
        exit(0)

    print(f"Found {len(sorted_files)} files to import.")

    for i, file_path in enumerate(sorted_files):
        # Progress indicator
        print(f"Processing {i+1}/{len(sorted_files)}: {os.path.basename(file_path)}")
        import_resource(token, file_path)

    print(f"\nImport process completed. Check response logs at: {RESPONSE_LOG_PATH}")
