import argparse
import requests
import string
import random
import base64
import hashlib
from urllib.parse import urlparse, parse_qs
import json
import sys

def generate_pkce_pair():
    # Generate verifier
    verifier = ''.join(random.choices(string.ascii_letters + string.digits + '-._~', k=128))
    
    # Generate challenge
    digest = hashlib.sha256(verifier.encode('ascii')).digest()
    challenge = base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')
    
    return verifier, challenge


def main():
    parser = argparse.ArgumentParser(description="SMART on FHIR Headless Query Script")
    parser.add_argument("--resource-name", required=True, help="FHIR Resource Type (e.g., Patient, Encounter)")
    parser.add_argument("--resource-id", required=True, help="FHIR Resource ID")
    parser.add_argument("--base-url", default="https://digressingly-auriferous-lee.ngrok-free.dev/fhir", help="FHIR Server Base URL")
    parser.add_argument("--aud", default="https://digressingly-auriferous-lee.ngrok-free.dev/fhir", help="Audience parameter for consent")
    
    args = parser.parse_args()
    
    base_url = args.base_url.rstrip("/")
    aud_url = args.aud.rstrip("/")
    resource_name = args.resource_name
    resource_id = args.resource_id
    
    # 1. Provide consent to get authorization code
    print(f"[*] Requesting authorization code for {resource_name}/{resource_id}...")
    
    verifier, challenge = generate_pkce_pair()
    state = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    client_id = "test_smart_client"
    redirect_uri = "http://localhost/callback"
    
    # We dynamically request scope based on the resource name, e.g., patient/Patient.read or patient/*.read
    scope = f"launch/patient patient/{resource_name}.read openid fhirUser"
    
    consent_data = {
        "decision": "approve",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "aud": aud_url,
        "approved_scopes": scope
    }
    
    consent_url = f"{base_url}/auth/consent"
    
    try:
        response = requests.post(consent_url, data=consent_data, allow_redirects=False)
        
        if response.status_code not in (301, 302, 303, 307, 308):
            print(f"[-] Failed to get redirect from consent endpoint. Status: {response.status_code}")
            print(response.text)
            sys.exit(1)
            
        location = response.headers.get("Location")
        if not location:
            print("[-] No Location header found in consent response.")
            sys.exit(1)
            
        parsed_url = urlparse(location)
        query_params = parse_qs(parsed_url.query)
        
        if "error" in query_params:
            print(f"[-] Authorization error: {query_params.get('error')}")
            sys.exit(1)
            
        code = query_params.get("code")
        if not code:
            print("[-] No authorization code found in redirect URI.")
            sys.exit(1)
            
        auth_code = code[0]
        print(f"[+] Obtained Authorization Code")
        
    except Exception as e:
        print(f"[-] Error during consent request: {e}")
        sys.exit(1)


    # 2. Exchange authorization code for token
    print(f"[*] Exchanging authorization code for access token...")
    token_url = f"{base_url}/auth/token"
    token_data = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_verifier": verifier
    }
    
    try:
        token_res = requests.post(token_url, data=token_data)
        if token_res.status_code != 200:
            print(f"[-] Token exchange failed. Status: {token_res.status_code}")
            print(token_res.text)
            sys.exit(1)
            
        token_json = token_res.json()
        access_token = token_json.get("access_token")
        
        if not access_token:
            print("[-] No access token found in token response.")
            sys.exit(1)
            
        print("[+] Successfully obtained Access Token")
        
    except Exception as e:
        print(f"[-] Error during token exchange: {e}")
        sys.exit(1)


    # 3. Query the FHIR Resource
    print(f"[*] Querying FHIR Resource: {resource_name}/{resource_id}")
    query_url = f"{base_url}/{resource_name}/{resource_id}"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/fhir+json"
    }
    
    try:
        res = requests.get(query_url, headers=headers)
        if res.status_code == 200:
            print(f"\n[+] Successfully retrieved {resource_name}/{resource_id}:")
            print(json.dumps(res.json(), indent=2))
        else:
            print(f"[-] Failed to fetch resource. Status: {res.status_code}")
            print(res.text)
    except Exception as e:
        print(f"[-] Error during FHIR query: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
