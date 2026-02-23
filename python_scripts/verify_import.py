import urllib.request
import urllib.parse
import urllib.error
import json
import base64
import hashlib
import secrets
import ssl
import re

# Configuration
BASE_URL = "https://digressingly-auriferous-lee.ngrok-free.dev"
REDIRECT_URI = "http://localhost:8080/"
CLIENT_ID = "my-client"

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
        "scope": "openid profile launch/patient user/*.write user/*.read",
    }
    
    params_list = list(params.items())
    params_list.append(("approved_scopes", "openid"))
    params_list.append(("approved_scopes", "profile"))
    params_list.append(("approved_scopes", "launch/patient"))
    params_list.append(("approved_scopes", "user/*.write"))
    params_list.append(("approved_scopes", "user/*.read"))
    
    data = urllib.parse.urlencode(params_list).encode('utf-8')
    
    req = urllib.request.Request(consent_url, data=data, method="POST")
    https_handler = urllib.request.HTTPSHandler(context=ctx)
    opener = urllib.request.build_opener(https_handler, NoRedirectHandler)
    
    try:
        with opener.open(req) as response:
            if response.code in [302, 303, 301, 307]:
                location = response.headers.get('Location')
                match = re.search(r'code=([^&]+)', location)
                if match:
                    return match.group(1), code_verifier
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
            return token_json.get('access_token')
    except Exception as e:
        print(f"   Error: {e}")
        return None

def check_resource(token, resource_type, resource_id):
    url = f"{BASE_URL}/fhir/{resource_type}/{resource_id}"
    print(f"Checking {url}...")
    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    
    try:
        with urllib.request.urlopen(req, context=ctx) as response:
            if response.code == 200:
                print(f"   [OK] Found {resource_type}/{resource_id}")
                return True
    except urllib.error.HTTPError as e:
        print(f"   [FAIL] {e.code} {e.reason}")
    except Exception as e:
        print(f"   [FAIL] {e}")
    return False

def main():
    print("Authenticating...")
    code, verifier = get_access_token()
    if not code:
        print("Auth failed.")
        return
    token = exchange_token(code, verifier)
    if not token:
        print("Token exchange failed.")
        return

    print("\nVerifying imported resources...")
    p85 = check_resource(token, "Patient", "85")
    p86 = check_resource(token, "Patient", "86")
    
    if p85 and p86:
        print("\nSUCCESS: Both patients found.")
    else:
        print("\nWARNING: Some resources are missing.")

if __name__ == "__main__":
    main()
