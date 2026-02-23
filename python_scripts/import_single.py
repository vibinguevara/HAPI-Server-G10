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
FILE_PATH = r"c:\Labs\hwsafe\Analysis\sl-implementation-g10\hapi-fhir-jpaserver-starter-master\hapi-fhir-jpaserver-starter-master\src\main\resources\fhir-resources\us-core-capability-statement\CapabilityStatement-us-core-client.json"
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
    token = get_access_token()
    if not token:
        print("Could not get token. Exiting.")
        return

    # Import
    print(f"\nImporting {FILE_PATH}...")
    try:
        with open(FILE_PATH, 'r', encoding='utf-8') as f:
            resource_data = json.load(f)
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    resource_id = resource_data.get("id")
    if not resource_id:
        print("No ID found in resource. Cannot PUT.")
        return

    fhir_url = f"{BASE_URL}/fhir/CapabilityStatement/{resource_id}"
    print(f"PUT {fhir_url}")
    
    json_body = json.dumps(resource_data).encode('utf-8')
    req = urllib.request.Request(fhir_url, data=json_body, method="PUT")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json") # try standard json

    try:
        with urllib.request.urlopen(req, context=ctx) as response:
            print(f"Import Success: {response.status}")
    except urllib.error.HTTPError as e:
        print(f"Import Failed: {e.code} {e.reason}")
        try:
            print(e.read().decode('utf-8'))
        except:
            pass
        return

    # Verify
    print(f"\nVerifying via GET {BASE_URL}/fhir/metadata...")
    url = f"{BASE_URL}/fhir/metadata"
    req = urllib.request.Request(url, method="GET")
    # Using token for metadata just in case, though usually public
    req.add_header("Authorization", f"Bearer {token}")
    
    try:
        with urllib.request.urlopen(req, context=ctx) as response:
            data = response.read().decode('utf-8')
            print(f"Verification Success: {response.status}")
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write(data)
            print(f"Response saved to {OUTPUT_FILE}")
    except urllib.error.HTTPError as e:
        print(f"Verification Failed: {e.code} {e.reason}")
        try:
            print(e.read().decode('utf-8'))
        except:
            pass

if __name__ == "__main__":
    main()
