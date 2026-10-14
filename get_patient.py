#!/usr/bin/env python3
"""
get_patient.py - Retrieve Patients from HAPI FHIR Server with OAuth2 / SMART on FHIR.

Server Details:
- Base URL: https://mofapi.medicalofficeforce.co/fhir
- Client ID: 4a48eeb3-4650-423a-af4d-fe62c5f4753d
- Client Secret: a61a2099-d9b2-40bb-8c63-b20883f635e1
- Redirect URI: https://oauth.pstmn.io/v1/browser-callback
"""

import argparse
import base64
import hashlib
import json
import secrets
import sys
from urllib.parse import parse_qs, urlparse
import requests

DEFAULT_BASE_URL = "https://mofapi.medicalofficeforce.co/fhir"
DEFAULT_CLIENT_ID = "4a48eeb3-4650-423a-af4d-fe62c5f4753d"
DEFAULT_CLIENT_SECRET = "a61a2099-d9b2-40bb-8c63-b20883f635e1"
DEFAULT_REDIRECT_URI = "https://oauth.pstmn.io/v1/browser-callback"
DEFAULT_SCOPES = "launch openid fhirUser offline_access user/*.read user/*.* patient/*.read"


def generate_pkce_pair():
    """Generates PKCE code_verifier and code_challenge (RFC 7636, S256)."""
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
    return code_verifier, code_challenge


def get_access_token(base_url, client_id, client_secret, redirect_uri, scope):
    """Executes full SMART on FHIR Authorization Code + PKCE flow to acquire Access Token."""
    code_verifier, code_challenge = generate_pkce_pair()
    state = secrets.token_hex(8)

    print("[*] Step 1: Requesting Authorization Code from:")
    print(f"    {base_url}/auth/authorize")

    auth_params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "aud": base_url,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    try:
        r_auth = requests.get(f"{base_url}/auth/authorize", params=auth_params, timeout=15)
        if r_auth.status_code != 200:
            print(f"[-] Authorization request failed with HTTP {r_auth.status_code}: {r_auth.text}")
            sys.exit(1)
    except Exception as e:
        print(f"[-] Error connecting to authorize endpoint: {e}")
        sys.exit(1)

    print("[+] Step 2: Submitting Consent Approval...")
    consent_data = {
        "decision": "approve",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "aud": base_url,
        "approved_scopes": scope.split(),
    }

    try:
        r_consent = requests.post(
            f"{base_url}/auth/consent",
            data=consent_data,
            allow_redirects=False,
            timeout=15,
        )
        if r_consent.status_code not in (301, 302, 303, 307):
            print(f"[-] Consent failed with status {r_consent.status_code}: {r_consent.text}")
            sys.exit(1)

        location = r_consent.headers.get("Location")
        if not location:
            print("[-] Redirect location missing in consent response.")
            sys.exit(1)

        parsed_query = parse_qs(urlparse(location).query)
        if "error" in parsed_query:
            print(f"[-] Authorization error returned: {parsed_query.get('error')}")
            sys.exit(1)

        auth_code = parsed_query["code"][0]
        print(f"[+] Obtained Authorization Code: {auth_code[:8]}...")
    except Exception as e:
        print(f"[-] Error submitting consent: {e}")
        sys.exit(1)

    print("[*] Step 3: Exchanging Authorization Code for Access Token at /auth/token...")
    token_data = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": code_verifier,
    }

    basic_auth_str = f"{client_id}:{client_secret}"
    basic_auth_b64 = base64.b64encode(basic_auth_str.encode("utf-8")).decode("utf-8")
    token_headers = {
        "Authorization": f"Basic {basic_auth_b64}",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    try:
        r_token = requests.post(
            f"{base_url}/auth/token",
            data=token_data,
            headers=token_headers,
            timeout=15,
        )
        if r_token.status_code != 200:
            print(f"[-] Token exchange failed with HTTP {r_token.status_code}: {r_token.text}")
            sys.exit(1)

        token_response = r_token.json()
        access_token = token_response.get("access_token")
        if not access_token:
            print(f"[-] Access token missing from response: {token_response}")
            sys.exit(1)

        print("[+] Access Token successfully acquired!")
        expires_in = token_response.get("expires_in", "unknown")
        print(f"    Token Type: {token_response.get('token_type', 'Bearer')}, Expires In: {expires_in}s")
        return access_token
    except Exception as e:
        print(f"[-] Error exchanging token: {e}")
        sys.exit(1)


def get_patients(base_url, access_token, patient_id=None, count=20, output_file=None):
    """Performs GET call to /Patient."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/fhir+json",
    }

    if patient_id:
        url = f"{base_url}/Patient?_id={patient_id}"
        print(f"\n[*] Sending GET request for Patient with ID: {patient_id}")
    else:
        url = f"{base_url}/Patient?_count={count}"
        print(f"\n[*] Sending GET request for List of Patients:")
    print(f"    URL: {url}")

    try:
        response = requests.get(url, headers=headers, timeout=20)
        print(f"[+] HTTP Status Code: {response.status_code}")

        if response.status_code != 200:
            print(f"[-] Request failed: {response.text}")
            return

        data = response.json()

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            print(f"[+] Saved response JSON to: {output_file}")

        print("\n" + "=" * 70)
        print("                   FHIR SERVER RESPONSE                    ")
        print("=" * 70)

        resource_type = data.get("resourceType")
        total = data.get("total")
        entries = data.get("entry", [])

        print(f"Resource Type : {resource_type}")
        if total is not None:
            print(f"Total Matches : {total}")
        print(f"Entries Found : {len(entries)}")

        if entries:
            print("-" * 70)
            print(f"{'ID':<20} | {'Name':<25} | {'Gender':<8} | {'Birth Date':<12}")
            print("-" * 70)
            for entry in entries:
                res = entry.get("resource", {})
                pid = res.get("id", "<no-id>")
                gender = res.get("gender", "-")
                birth_date = res.get("birthDate", "-")

                names = res.get("name", [])
                full_name = "-"
                if names:
                    primary_name = names[0]
                    given = " ".join(primary_name.get("given", []))
                    family = primary_name.get("family", "")
                    full_name = f"{given} {family}".strip()

                print(f"{pid:<20} | {full_name[:25]:<25} | {gender:<8} | {birth_date:<12}")

        print("=" * 70)
        print("\nFull JSON Response:")
        print(json.dumps(data, indent=2))

    except Exception as e:
        print(f"[-] Error fetching patients: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Get Patients from HAPI FHIR Server via SMART on FHIR OAuth2")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help=f"FHIR Base URL (default: {DEFAULT_BASE_URL})")
    parser.add_argument("--client-id", default=DEFAULT_CLIENT_ID, help="OAuth2 Client ID")
    parser.add_argument("--client-secret", default=DEFAULT_CLIENT_SECRET, help="OAuth2 Client Secret")
    parser.add_argument("--redirect-uri", default=DEFAULT_REDIRECT_URI, help="OAuth2 Redirect URI")
    parser.add_argument("--scope", default=DEFAULT_SCOPES, help="OAuth2 Scopes")
    parser.add_argument("--id", dest="patient_id", default=None, help="Optional specific Patient ID")
    parser.add_argument("--count", type=int, default=20, help="Number of patients to retrieve per page (default: 20)")
    parser.add_argument("--token", default=None, help="Use an existing Bearer token directly")
    parser.add_argument("--output", default=None, help="Save JSON response to file")

    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")

    if args.token:
        access_token = args.token
    else:
        access_token = get_access_token(
            base_url=base_url,
            client_id=args.client_id,
            client_secret=args.client_secret,
            redirect_uri=args.redirect_uri,
            scope=args.scope,
        )

    get_patients(
        base_url=base_url,
        access_token=access_token,
        patient_id=args.patient_id,
        count=args.count,
        output_file=args.output,
    )


if __name__ == "__main__":
    main()
