import argparse
import requests
import string
import random
import base64
import hashlib
from urllib.parse import urlparse, parse_qs
import json
import sys
import urllib3
import urllib.parse
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def generate_pkce_pair():
    verifier = ''.join(random.choices(string.ascii_letters + string.digits + '-._~', k=128))
    digest = hashlib.sha256(verifier.encode('ascii')).digest()
    challenge = base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')
    return verifier, challenge

def get_access_token(base_url, aud_url):
    print(f"[*] Obtaining access token via SMART on FHIR...")
    
    verifier, challenge = generate_pkce_pair()
    state = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    client_id = "test_smart_client"
    redirect_uri = "http://localhost/callback"
    scope = "launch/patient patient/Condition.rs?category=http://terminology.hl7.org/CodeSystem/condition-category|encounter-diagnosis openid fhirUser"
    
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
        response = requests.post(consent_url, data=consent_data, allow_redirects=False, verify=False)
        if response.status_code not in (301, 302, 303, 307, 308):
            print(f"[-] Failed to get redirect from consent endpoint. Status: {response.status_code}")
            sys.exit(1)
            
        location = response.headers.get("Location")
        parsed_url = urlparse(location)
        query_params = parse_qs(parsed_url.query)
        
        if "error" in query_params:
            print(f"[-] Authorization error: {query_params.get('error')}")
            sys.exit(1)
            
        auth_code = query_params.get("code")[0]
        
    except Exception as e:
        print(f"[-] Error during consent request: {e}")
        sys.exit(1)

    token_url = f"{base_url}/auth/token"
    token_data = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_verifier": verifier
    }
    
    try:
        token_res = requests.post(token_url, data=token_data, verify=False)
        if token_res.status_code != 200:
            print(f"[-] Token exchange failed. Status: {token_res.status_code}")
            sys.exit(1)
            
        access_token = token_res.json().get("access_token")
        print("[+] Successfully obtained Access Token")
        return access_token
    except Exception as e:
        print(f"[-] Error during token exchange: {e}")
        sys.exit(1)

def execute_query(url, access_token):
    print(f"\n[*] Executing Query:")
    print(f"    {url}")
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/fhir+json"
    }
    
    try:
        res = requests.get(url, headers=headers, verify=False)
        
        script_dir = os.path.dirname(os.path.abspath(__file__))
        troubleshoot_file = os.path.join(script_dir, "granular_scope_troubleshoot.txt")
        try:
            with open(troubleshoot_file, "w", encoding="utf-8") as f:
                try:
                    f.write(json.dumps(res.json(), indent=2))
                except:
                    f.write(res.text)
        except Exception as e:
            print(f"    [-] Failed to write to troubleshoot file: {e}")

        if res.status_code == 200:
            data = res.json()
            if data.get('resourceType') == 'Bundle':
                total = data.get('total', 'unknown')
                entries = len(data.get('entry', []))
                print(f"    [+] Success! Status Code: {res.status_code}. Found {entries} entries (total: {total}).")
            else:
                print(f"    [+] Success! Status Code: {res.status_code}. Retrieved single resource {data.get('resourceType')}/{data.get('id')}.")
        else:
            print(f"    [-] Failed. Status Code: {res.status_code}")
            try:
                print(f"    {json.dumps(res.json(), indent=2)}")
            except:
                print(f"    {res.text}")
    except Exception as e:
        print(f"    [-] Request failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="Execute Condition Queries")
    parser.add_argument("--base-url", default="https://digressingly-auriferous-lee.ngrok-free.dev/fhir", help="FHIR Server Base URL")
    parser.add_argument("--aud", default="https://digressingly-auriferous-lee.ngrok-free.dev/fhir", help="Audience parameter for consent")
    
    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")
    aud_url = args.aud.rstrip("/")
    
    # 1. Get token
    access_token = get_access_token(base_url, aud_url)
    
    if not access_token:
        print("[-] Failed to retrieve access token.")
        sys.exit(1)
        
    # 2. Execute queries
    queries = [
        # https://digressingly-auriferous-lee.ngrok-free.dev/fhir/Condition?category=problem-list-item&patient=mof-85
        f"{base_url}/Condition?category=problem-list-item&patient=mof-85"
       # f"{base_url}/Condition?category=encounter-diagnosis&patient=Patient/mof-85",
       # f"{base_url}/Condition?category=http://terminology.hl7.org/CodeSystem/condition-category|encounter-diagnosis&patient=mof-85",
       # f"{base_url}/Condition/118c7c21-e66b-2d06-554f-cc424af10f3c"
    ]
    
    for query in queries:
        execute_query(query, access_token)

if __name__ == "__main__":
    main()
