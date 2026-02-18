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

# Configuration
BASE_URL = "https://digressingly-auriferous-lee.ngrok-free.dev"
REDIRECT_URI = "http://localhost:8080/"
CLIENT_ID = "my-client"
BUNDLE_DIR = r"c:\Labs\hwsafe\Analysis\sl-implementation-g10\hapi-fhir-jpaserver-starter-master\hapi-fhir-jpaserver-starter-master\src\main\resources\fhir-resources\singlePatientInfernoG10"
FILES_TO_IMPORT = [
    "single_patient_fhir_85_write.json"
]

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
    print("1. Generating PKCE...")
    code_verifier, code_challenge = generate_pkce()
    state = secrets.token_urlsafe(16)

    print("2. Requesting Authorization Code...")
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
    # Use HTTPS handler for ngrok
    https_handler = urllib.request.HTTPSHandler(context=ctx)
    opener = urllib.request.build_opener(https_handler, NoRedirectHandler)
    
    try:
        with opener.open(req) as response:
            if response.code in [302, 303, 301, 307]:
                location = response.headers.get('Location')
                print(f"   Redirected to: {location}")
                match = re.search(r'code=([^&]+)', location)
                if match:
                    code = match.group(1)
                    print(f"   Authorization Code: {code}")
                    return code, code_verifier
                else:
                    print("   Error: Could not find code in redirect URL")
                    return None, None
            else:
                print(f"   Error: Expected 302 Redirect, got {response.code}")
                return None, None
    except urllib.error.HTTPError as e:
        print(f"   HTTP Error: {e.code} {e.reason}")
        return None, None
    except Exception as e:
        print(f"   Error: {e}")
        return None, None

def exchange_token(code, code_verifier):
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

def import_resource(access_token, resource):
    resource_type = resource.get("resourceType")
    resource_id = resource.get("id")
    
    if not resource_type:
        print("   Skipping entry without resourceType")
        return

    if resource_id:
        fhir_url = f"{BASE_URL}/fhir/{resource_type}/{resource_id}"
        method = "PUT"
        print(f"   Putting {resource_type}/{resource_id}...", end="")
    else:
        fhir_url = f"{BASE_URL}/fhir/{resource_type}"
        method = "POST"
        print(f"   Posting {resource_type}...", end="")
    
    json_body = json.dumps(resource).encode('utf-8')
    
    req = urllib.request.Request(fhir_url, data=json_body, method=method)
    req.add_header("Authorization", f"Bearer {access_token}")
    req.add_header("Content-Type", "application/fhir+json")
    
    retry_count = 0
    max_retries = 3
    
    while retry_count < max_retries:
        try:
            # 5 second timeout for the request
            with urllib.request.urlopen(req, context=ctx, timeout=30) as response:
                print(f" Success: {response.status}")
                return
        except (urllib.error.HTTPError, urllib.error.URLError, Exception) as e:
            # Catching generic Exception to handle the SSL EOF error which might be wrapped
            retry_count += 1
            print(f" Failed (Attempt {retry_count}/{max_retries}): {e}")
            if retry_count >= max_retries:
                 # If it was an HTTPError, try to print the body
                if isinstance(e, urllib.error.HTTPError):
                    try:
                        print(e.read().decode('utf-8'))
                    except:
                        pass
            else:
                import time
                time.sleep(2) # Wait 2 seconds before retrying
    
    # Small delay to prevent overwhelming the server
    import time
    time.sleep(0.5)

def main():
    code, code_verifier = get_access_token()
    if not code:
        print("Could not get auth code. Exiting.")
        return

    token = exchange_token(code, code_verifier)
    if not token:
        print("Could not get token. Exiting.")
        return

    for filename in FILES_TO_IMPORT:
        file_path = os.path.join(BUNDLE_DIR, filename)
        if not os.path.exists(file_path):
            print(f"\nFile not found: {file_path}")
            continue
            
        print(f"\nProcessing file: {filename}")
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                bundle = json.load(f)
                
            if bundle.get("resourceType") != "Bundle":
                print("   File is not a Bundle. Attempting single resource import.")
                import_resource(token, bundle)
                continue
                
            entries = bundle.get("entry", [])
            print(f"   Found {len(entries)} entries.")
            
            for entry in entries:
                resource = entry.get("resource")
                if resource:
                    import_resource(token, resource)
                    
        except Exception as e:
            print(f"   Error processing file {filename}: {e}")

if __name__ == "__main__":
    main()
