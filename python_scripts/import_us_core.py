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
LOG_FILE_PATH = os.path.join(RESOURCE_BASE_DIR, "import_log.txt")

# Define resource types and directories in order
RESOURCE_ORDER = [
    {
        "type": "CapabilityStatement",
        "dir": os.path.join(RESOURCE_BASE_DIR, "us-core-capability-statement")
    },
    {
        "type": "CodeSystem",
        "dir": os.path.join(RESOURCE_BASE_DIR, "us-core-code-system")
    },
    {
        "type": "SearchParameter",
        "dir": os.path.join(RESOURCE_BASE_DIR, "us-core-search-parameters")
    },
    {
        "type": "StructureDefinition",
        "dir": os.path.join(RESOURCE_BASE_DIR, "us-core-structured-definition")
    },
    {
        "type": "ValueSet",
        "dir": os.path.join(RESOURCE_BASE_DIR, "us-core-value-set")
    }
]

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
    # user/*.write covers most resource writes
    
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
        print(e.read().decode('utf-8'))
        return None

def log_result(resource_type, file_name, status, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] IMPORT {status}: {resource_type} from {file_name} - {message}\n"
    print(log_entry.strip())
    try:
        with open(LOG_FILE_PATH, "a") as log_file:
            log_file.write(log_entry)
    except Exception as e:
        print(f"Error writing to log file: {e}")

def import_resource(access_token, file_path, resource_type):
    file_name = os.path.basename(file_path)
    print(f"Importing {resource_type} from {file_name}...")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            resource_data = json.load(f)
    except Exception as e:
        log_result(resource_type, file_name, "FAILURE", f"File read error: {str(e)}")
        return

    # Check ID for PUT vs POST
    resource_id = resource_data.get("id")
    
    if resource_id:
        # print(f"   ID: {resource_id} (PUT)")
        fhir_url = f"{BASE_URL}/fhir/{resource_type}/{resource_id}"
        method = "PUT"
    else:
        # print(f"   No ID (POST)")
        fhir_url = f"{BASE_URL}/fhir/{resource_type}"
        method = "POST"
    
    json_body = json.dumps(resource_data).encode('utf-8')
    
    req = urllib.request.Request(fhir_url, data=json_body, method=method)
    req.add_header("Authorization", f"Bearer {access_token}")
    req.add_header("Content-Type", "application/fhir+json")
    
    try:
        with urllib.request.urlopen(req, context=ctx) as response:
            if response.status in [200, 201]:
                location = response.headers.get('Location', 'No Location Header')
                log_result(resource_type, file_name, "SUCCESS", f"Status: {response.status}, Location: {location}")
            else:
                log_result(resource_type, file_name, "WARNING", f"Unexpected Status: {response.status}")
            
    except urllib.error.HTTPError as e:
        error_msg = f"HTTP {e.code} {e.reason}"
        try:
            body = e.read().decode('utf-8')
            # Extract issue diagnostics if available
            try:
                oo = json.loads(body)
                if 'issue' in oo and len(oo['issue']) > 0:
                     diag = oo['issue'][0].get('diagnostics', 'No diagnostics')
                     error_msg += f" - {diag}"
            except:
                pass
        except:
            pass
        log_result(resource_type, file_name, "FAILURE", error_msg)
    except Exception as e:
        log_result(resource_type, file_name, "FAILURE", f"Exception: {str(e)}")

if __name__ == "__main__":
    print("Starting US Core Import Process...")
    
    # Initialize log file
    with open(LOG_FILE_PATH, "a") as f:
        f.write("\n--- New Import Session ---\n")

    token = get_access_token()
    
    if not token:
        print("Failed to obtain access token. Aborting.")
        exit(1)
        
    for item in RESOURCE_ORDER:
        resource_type = item["type"]
        directory = item["dir"]
        
        print(f"\n--- Processing {resource_type} ---")
        if not os.path.isdir(directory):
            print(f"Directory not found: {directory}")
            continue
            
        json_files = glob.glob(os.path.join(directory, "*.json"))
        if not json_files:
             print(f"No JSON files found in {directory}")
             continue
             
        for file_path in json_files:
            import_resource(token, file_path, resource_type)

    print("\nImport process completed. Check log for details.")
