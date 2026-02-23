import urllib.request
import urllib.parse
import urllib.error
import json
import base64
import hashlib
import secrets
import ssl
import re

# Disable SSL warnings/verification for localhost
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

BASE_URL = "https://localhost:8080"
REDIRECT_URI = "http://localhost:8080/"
CLIENT_ID = "my-client"
PATIENT_FILE_PATH = "src/main/resources/fhir-resources/patient_fhir_resource.json"

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
    
    # Simulate the consent form submission
    params = {
        "decision": "allow",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "scope": "openid profile launch/patient patient/*.write",
    }
    
    # We want "approved_scopes" to be repeated
    params_list = list(params.items())
    params_list.append(("approved_scopes", "openid"))
    params_list.append(("approved_scopes", "profile"))
    params_list.append(("approved_scopes", "launch/patient"))
    params_list.append(("approved_scopes", "patient/*.write"))
    
    data = urllib.parse.urlencode(params_list).encode('utf-8')
    
    print(f"   POST {consent_url}")
    
    req = urllib.request.Request(consent_url, data=data, method="POST")
    opener = urllib.request.build_opener(NoRedirectHandler)
    
    try:
        # We need to pass the SSL context to the opener's handler, but build_opener doesn't take context.
        # However, HTTPSHandler takes context.
        https_handler = urllib.request.HTTPSHandler(context=ctx)
        opener = urllib.request.build_opener(https_handler, NoRedirectHandler)
        
        with opener.open(req) as response:
            # If 302, NoRedirectHandler returns the response object (fp)
            # But the status code might be accessible via response.code or response.status
             
            if response.code in [302, 303, 301, 307]:
                location = response.headers.get('Location')
                print(f"   Redirected to: {location}")
                
                # Extract code from URL
                match = re.search(r'code=([^&]+)', location)
                if match:
                    code = match.group(1)
                    print(f"   Authorization Code: {code}")
                else:
                    print("   Error: Could not find code in redirect URL")
                    return None
            else:
                print(f"   Error: Expected 302 Redirect, got {response.code}")
                print(response.read().decode('utf-8'))
                return None

    except urllib.error.HTTPError as e:
        # If it's a 302 that wasn't followed (unlikely with urlopen) or other error
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
            print("   Access Token obtained successfully")
            return access_token
    except urllib.error.HTTPError as e:
        print(f"   HTTP Error: {e.code} {e.reason}")
        print(e.read().decode('utf-8'))
        return None

def import_patient(access_token):
    print("4. Reading Patient Resource...")
    try:
        with open(PATIENT_FILE_PATH, 'r', encoding='utf-8') as f:
            patient_data = json.load(f)
    except FileNotFoundError:
        print(f"   Error: File not found at {PATIENT_FILE_PATH}")
        return

    print("5. Posting Patient Resource...")
    fhir_url = f"{BASE_URL}/fhir/Patient"
    
    # Convert back to JSON string for body
    json_body = json.dumps(patient_data).encode('utf-8')
    
    req = urllib.request.Request(fhir_url, data=json_body, method="POST")
    req.add_header("Authorization", f"Bearer {access_token}")
    req.add_header("Content-Type", "application/fhir+json")
    
    try:
        with urllib.request.urlopen(req, context=ctx) as response:
            print(f"   Success! Status: {response.status}")
            print(f"   Location: {response.headers.get('Location')}")
            print(f"   Response Body: {response.read().decode('utf-8')}")
    except urllib.error.HTTPError as e:
        print(f"   Error: {e.code} {e.reason}")
        print(e.read().decode('utf-8'))

if __name__ == "__main__":
    token = get_access_token()
    if token:
        import_patient(token)
