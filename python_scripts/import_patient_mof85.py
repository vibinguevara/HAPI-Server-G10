#!/usr/bin/env python3
"""
Import Patient mof-85 into FHIR Server

This script:
1. Obtains an OAuth 2.0 SMART on FHIR access token using the 'client_credentials' grant
   with the registered client ID and 'system/*.rs' scope.
2. Reads the patient transaction bundle JSON file (mof-85_Patient.json).
3. Posts the transaction bundle to the FHIR endpoint (POST /fhir).
4. Verifies the patient record by querying GET /fhir/Patient/mof-85.
"""

import argparse
import json
import os
import sys
from pathlib import Path
import urllib3
import requests

# Suppress insecure HTTPS request warnings if self-signed or proxy certificates are used
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_BASE_URL = os.getenv("BASE_URL", "https://mofapi.medicalofficeforce.co")
DEFAULT_CLIENT_ID = os.getenv("CLIENT_ID", "685fb6bb-831c-4335-ac1a-3ddb1aec016d")
DEFAULT_SCOPE = os.getenv("SCOPE", "system/*.rs")

def find_bundle_file(user_path: str = None) -> Path:
    """Resolve the location of mof-85_Patient.json."""
    if user_path and os.path.exists(user_path):
        return Path(user_path).resolve()

    candidate_rel_paths = [
        "src/main/resources/fhir-resources/singlePatientInfernoG10/mof-85_Patient.json",
        "src/main/resources/SinglePatientInfernoG10/mof-85_Patient.json",
        "fhir-resources/singlePatientInfernoG10/mof-85_Patient.json",
        "singlePatientInfernoG10/mof-85_Patient.json",
        "mof-85_Patient.json"
    ]

    # Check relative to current working directory
    for rel in candidate_rel_paths:
        p = Path.cwd() / rel
        if p.is_file():
            return p.resolve()

    # Check relative to script directory and its parent (repo root)
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent
    for rel in candidate_rel_paths:
        p = repo_root / rel
        if p.is_file():
            return p.resolve()
        p_sub = script_dir / rel
        if p_sub.is_file():
            return p_sub.resolve()

    raise FileNotFoundError(
        "Could not find 'mof-85_Patient.json'. Please specify the file location with --bundle-path."
    )

def get_access_token(base_url: str, client_id: str, scope: str, verify_ssl: bool = False) -> str:
    """Request an OAuth2 Bearer token using client_credentials grant."""
    base = base_url.rstrip("/")
    token_url = f"{base}/fhir/auth/token"

    print(f"[*] Requesting access token from: {token_url}")
    print(f"    - Client ID : {client_id}")
    print(f"    - Grant Type: client_credentials")
    print(f"    - Scope     : {scope}")

    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "scope": scope
    }

    try:
        response = requests.post(token_url, data=data, verify=verify_ssl, timeout=30)
    except Exception as e:
        # Fallback to /auth/token if /fhir/auth/token fails with connection issue
        fallback_url = f"{base}/auth/token"
        print(f"[!] Request to {token_url} failed ({e}), trying fallback: {fallback_url}...")
        response = requests.post(fallback_url, data=data, verify=verify_ssl, timeout=30)

    if response.status_code != 200:
        print(f"[-] Failed to obtain access token! Status: {response.status_code}")
        print(f"    Response: {response.text}")
        sys.exit(1)

    token_data = response.json()
    access_token = token_data.get("access_token")
    if not access_token:
        print(f"[-] 'access_token' not found in response: {token_data}")
        sys.exit(1)

    expires_in = token_data.get("expires_in", "unknown")
    granted_scope = token_data.get("scope", scope)
    print(f"[+] Access token obtained successfully! (expires in: {expires_in}s, scope: {granted_scope})")
    return access_token

def import_patient_bundle(base_url: str, token: str, bundle_file: Path, verify_ssl: bool = False):
    """Post the transaction bundle to the FHIR endpoint."""
    base = base_url.rstrip("/")
    fhir_url = f"{base}/fhir"

    print(f"\n[*] Loading transaction bundle from: {bundle_file}")
    with open(bundle_file, "r", encoding="utf-8") as f:
        bundle_json = json.load(f)

    resource_type = bundle_json.get("resourceType")
    bundle_type = bundle_json.get("type")
    entries_count = len(bundle_json.get("entry", []))
    print(f"    - Bundle resourceType: {resource_type}")
    print(f"    - Bundle type        : {bundle_type}")
    print(f"    - Entries count      : {entries_count}")

    print(f"[*] Posting bundle to FHIR endpoint: {fhir_url}")
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/fhir+json",
        "Accept": "application/fhir+json"
    }

    response = requests.post(
        fhir_url,
        json=bundle_json,
        headers=headers,
        verify=verify_ssl,
        timeout=60
    )

    print(f"[*] Response Status Code: {response.status_code}")
    try:
        resp_json = response.json()
        print(f"[+] Transaction Response:\n{json.dumps(resp_json, indent=2)}")

        if response.status_code in (200, 201):
            for i, entry in enumerate(resp_json.get("entry", [])):
                resp_info = entry.get("response", {})
                status = resp_info.get("status")
                location = resp_info.get("location")
                print(f"    Entry #{i + 1}: status={status}, location={location}")
            print("\n[+] Patient mof-85 import completed successfully!")
        else:
            print(f"[-] Unexpected status code: {response.status_code}")
    except Exception:
        print(f"Response Body:\n{response.text}")

def verify_patient(base_url: str, token: str, patient_id: str = "mof-85", verify_ssl: bool = False):
    """Query GET /fhir/Patient/{patient_id} to verify resource exists."""
    base = base_url.rstrip("/")
    patient_url = f"{base}/fhir/Patient/{patient_id}"
    print(f"\n[*] Verifying imported patient at: {patient_url}")

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/fhir+json"
    }

    response = requests.get(patient_url, headers=headers, verify=verify_ssl, timeout=30)
    print(f"[*] Verification Status Code: {response.status_code}")

    if response.status_code == 200:
        patient = response.json()
        names = patient.get("name", [])
        name_str = "Unknown"
        if names:
            n = names[0]
            family = n.get("family", "")
            givens = " ".join(n.get("given", []))
            name_str = f"{givens} {family}".strip()
        birth_date = patient.get("birthDate", "N/A")
        gender = patient.get("gender", "N/A")
        print(f"[+] Patient verified successfully:")
        print(f"    - ID        : {patient.get('id')}")
        print(f"    - Name      : {name_str}")
        print(f"    - Gender    : {gender}")
        print(f"    - Birth Date: {birth_date}")
        print(f"    - VersionId : {patient.get('meta', {}).get('versionId')}")
        print(f"    - LastUpdate: {patient.get('meta', {}).get('lastUpdated')}")
    else:
        print(f"[-] Could not retrieve Patient/{patient_id}: {response.text}")

def main():
    parser = argparse.ArgumentParser(description="Import Patient mof-85 into FHIR server.")
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"FHIR server base URL (default: {DEFAULT_BASE_URL})"
    )
    parser.add_argument(
        "--client-id",
        default=DEFAULT_CLIENT_ID,
        help=f"Registered SMART Client ID (default: {DEFAULT_CLIENT_ID})"
    )
    parser.add_argument(
        "--scope",
        default=DEFAULT_SCOPE,
        help=f"OAuth2 scope to request (default: {DEFAULT_SCOPE})"
    )
    parser.add_argument(
        "--bundle-path",
        default=None,
        help="Path to mof-85_Patient.json (default: searches project resources)"
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip GET verification after bundle import"
    )
    parser.add_argument(
        "--strict-ssl",
        action="store_true",
        help="Enable strict SSL certificate validation"
    )

    args = parser.parse_args()
    verify_ssl = args.strict_ssl

    try:
        bundle_file = find_bundle_file(args.bundle_path)
    except FileNotFoundError as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

    print("==================================================")
    print("FHIR Patient Import: mof-85")
    print("==================================================")
    print(f"Target Server : {args.base_url}")
    print(f"Client ID     : {args.client_id}")
    print(f"Bundle File   : {bundle_file}")
    print("==================================================")

    token = get_access_token(
        base_url=args.base_url,
        client_id=args.client_id,
        scope=args.scope,
        verify_ssl=verify_ssl
    )

    import_patient_bundle(
        base_url=args.base_url,
        token=token,
        bundle_file=bundle_file,
        verify_ssl=verify_ssl
    )

    if not args.no_verify:
        verify_patient(
            base_url=args.base_url,
            token=token,
            patient_id="mof-85",
            verify_ssl=verify_ssl
        )

if __name__ == "__main__":
    main()
