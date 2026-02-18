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
OUTPUT_FILE = "capabilityStatement.json"

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
    # Add approved scopes
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

def main():
    code, code_verifier = get_access_token()
    if not code:
        print("Could not get auth code. Exiting.")
        return

    token = exchange_token(code, code_verifier)
    if not token:
        print("Could not get token. Exiting.")
        return

    # Verify
    print(f"\nVerifying via GET {BASE_URL}/fhir/metadata...")
    url = f"{BASE_URL}/fhir/metadata"
    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    
    try:
        with urllib.request.urlopen(req, context=ctx) as response:
            data = response.read().decode('utf-8')
            print(f"Verification Success: {response.status}")
            
            # Save to file
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write(data)
            print(f"Response saved to {OUTPUT_FILE}")

            # Check JSON
            try:
                metadata = json.loads(data)
                instantiates = metadata.get("instantiates", [])
                
                required_urls = [
                    "http://hl7.org/fhir/uv/bulkdata/CapabilityStatement/bulk-data",
                    "http://hl7.org/fhir/us/core/CapabilityStatement/us-core-server"
                ]
                
                print("\nChecking for 'instantiates' array...")
                if not instantiates:
                     print("FAIL: 'instantiates' array is missing or empty.")
                else:
                    print(f"Found 'instantiates': {instantiates}")
                    all_found = True
                    for url in required_urls:
                        if url in instantiates:
                            print(f"[OK] Found {url}")
                        else:
                            print(f"[MISSING] {url}")
                            all_found = False
                    
                    if all_found:
                        print("\nSUCCESS: All required URLs are present.")
                    else:
                        print("\nFAIL: Some URLs are missing.")

            except Exception as e:
                print(f"Error parsing JSON: {e}")

    except urllib.error.HTTPError as e:
        print(f"Verification Failed: {e.code} {e.reason}")
        try:
            print(e.read().decode('utf-8'))
        except:
            pass

if __name__ == "__main__":
    main()
