#!/usr/bin/env python3
"""
Convert Aidbox $everything Searchset Bundle to FHIR Transaction Bundle and Import to MOF Sandbox.

Job 1:
- Reads 'mof-85-searchset-responsejson.json'.
- Converts it into a FHIR R4 'type: transaction' Bundle.
- Removes searchset-specific fields ('search', 'fullUrl', 'link').
- Renames Patient ID '85' -> 'mof-85'.
- Maps all references to 'Patient/85' -> 'Patient/mof-85'.
- Maps references to 'Patient/86' -> 'Patient/mof-86'.
- Sanitizes proprietary Aidbox 'Session' references in AuditEvent.
- Adds PUT request headers to each entry: {"method": "PUT", "url": "<resourceType>/<id>"}.
- Saves the altered JSON to 'mof-85-transaction-bundle.json'.

Job 2:
- Authenticates with SMART on FHIR backend using Client ID 685fb6bb-831c-4335-ac1a-3ddb1aec016d.
- Ensures all prerequisite supporting resources referenced by the patient (Organizations, Practitioners, Locations, Roles, Endpoint) exist.
- Submits the transaction bundle to POST /fhir.
- Saves the complete server transaction response to a dedicated outcome file.
- Saves an itemized per-resource audit report of all imported resources.
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_BASE_URL = os.getenv("BASE_URL", "https://mofapi.medicalofficeforce.co")
DEFAULT_CLIENT_ID = os.getenv("CLIENT_ID", "685fb6bb-831c-4335-ac1a-3ddb1aec016d")
DEFAULT_SCOPE = os.getenv("SCOPE", "system/*.rs")
DEFAULT_INPUT_FILE = "src/main/resources/fhir-resources/mof-85-searchset-responsejson.json"
DEFAULT_OUTPUT_FILE = "src/main/resources/fhir-resources/mof-85-transaction-bundle.json"
DEFAULT_OUT_DIR = "import_outcomes"

PREREQUISITE_SUPPORTING_RESOURCES = [
    # Supporting Organizations
    {
        "resourceType": "Organization",
        "id": "56090ab7-1f97-37ff-a434-194f9c6e5510",
        "name": "PCP87052",
        "active": True
    },
    {
        "resourceType": "Organization",
        "id": "a9afd4c9-8443-3b5a-a486-07c3bb109b3f",
        "name": "RIVER BEND MEDICAL GROUP - CHICOPEE OFFICE - URGENT CARE",
        "active": True
    },
    # Supporting Locations
    {
        "resourceType": "Location",
        "id": "4c34c0db-7434-8c8f-1936-30dd023babc2",
        "name": "RIVER BEND MEDICAL GROUP - CHICOPEE OFFICE - URGENT CARE",
        "status": "active"
    },
    {
        "resourceType": "Location",
        "id": "690866aa-d2fd-8074-b448-3b7b0f1c84ad",
        "name": "PCP87052",
        "status": "active"
    },
    {
        "resourceType": "Location",
        "id": "70b2a52f-71ba-6ffe-9050-5daee15f4d88",
        "name": "HOLYOKE MEDICAL CENTER",
        "status": "active"
    },
    {
        "resourceType": "Location",
        "id": "ecd8399c-f381-beae-9a1c-afec249d4632",
        "name": "PCP170967",
        "status": "active"
    },
    # Supporting Practitioners
    {
        "resourceType": "Practitioner",
        "id": "eb10a604-ac01-3975-ad58-4c34606af456",
        "name": [{"text": "Dr. Patricia625 Kilback373", "family": "Kilback373", "given": ["Patricia625"], "prefix": ["Dr."]}]
    },
    {
        "resourceType": "Practitioner",
        "id": "8bee2ee3-d401-3728-9791-d235cfa01ab9",
        "name": [{"text": "Dr. Willena258 Oberbrunner298", "family": "Oberbrunner298", "given": ["Willena258"], "prefix": ["Dr."]}]
    },
    {
        "resourceType": "Practitioner",
        "id": "618787f5-2588-3dca-b90e-5e8fd27b1a36",
        "name": [{"text": "Dr. Blossom971 Christiansen251", "family": "Christiansen251", "given": ["Blossom971"], "prefix": ["Dr."]}]
    },
    {
        "resourceType": "Practitioner",
        "id": "cf8468d4-5a1b-3b05-8c92-7a82e2df0128",
        "name": [{"text": "Dr. Sammie902 DuBuque211", "family": "DuBuque211", "given": ["Sammie902"], "prefix": ["Dr."]}]
    },
    # Supporting PractitionerRoles
    {
        "resourceType": "PractitionerRole",
        "id": "0e919364-fe95-1dc4-e9aa-086aa29ee5ef",
        "practitioner": {"reference": "Practitioner/eb10a604-ac01-3975-ad58-4c34606af456"}
    },
    {
        "resourceType": "PractitionerRole",
        "id": "0f69d72e-4ab5-f549-9033-3b76d8695b97",
        "practitioner": {"reference": "Practitioner/8bee2ee3-d401-3728-9791-d235cfa01ab9"}
    },
    {
        "resourceType": "PractitionerRole",
        "id": "0fb6ec70-c81e-ad0f-ea17-2648668b0405",
        "practitioner": {"reference": "Practitioner/618787f5-2588-3dca-b90e-5e8fd27b1a36"}
    },
    {
        "resourceType": "PractitionerRole",
        "id": "8e81b028-5271-9eda-b6c0-0e308770ee50",
        "practitioner": {"reference": "Practitioner/cf8468d4-5a1b-3b05-8c92-7a82e2df0128"}
    },
    # Supporting Endpoint
    {
        "resourceType": "Endpoint",
        "id": "f85b5cca-bcf8-421c-bbcf-11db4dcb7e9c",
        "status": "active",
        "connectionType": {
            "system": "http://terminology.hl7.org/CodeSystem/endpoint-connection-type",
            "code": "hl7-fhir-rest"
        },
        "name": "FHIR API Endpoint",
        "address": "https://mofapi.medicalofficeforce.co/fhir/"
    }
]


def convert_searchset_to_transaction_bundle(input_path: Path, output_path: Path) -> dict:
    """Job 1: Convert Aidbox searchset JSON to a clean FHIR transaction bundle."""
    print(f"\n================================================================================")
    print(f"JOB 1: Converting Searchset Bundle to Transaction Bundle")
    print(f"================================================================================")
    print(f"Source Searchset File : {input_path}")
    print(f"Target Bundle File    : {output_path}")

    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    entries = data.get("entry", [])
    print(f"[*] Read {len(entries)} entries from searchset response.")

    new_entries = []
    type_counts = {}

    for idx, entry in enumerate(entries):
        resource = entry.get("resource", {})
        resource_type = resource.get("resourceType")
        resource_id = resource.get("id")

        if not resource_type or not resource_id:
            print(f"[-] Warning: Entry {idx} missing resourceType or id, skipping.")
            continue

        # Map Patient 85 -> mof-85
        if resource_type == "Patient" and resource_id == "85":
            resource["id"] = "mof-85"
            resource_id = "mof-85"

        # Replace all patient references recursively in JSON representation
        res_str = json.dumps(resource)
        res_str = res_str.replace('"reference": "Patient/85"', '"reference": "Patient/mof-85"')
        res_str = res_str.replace('"reference": "https://pobvbbhmgu.aidbox.app/Patient/85"', '"reference": "Patient/mof-85"')
        res_str = res_str.replace('"reference": "Patient/86"', '"reference": "Patient/mof-86"')
        res_str = res_str.replace('"reference": "https://pobvbbhmgu.aidbox.app/Patient/86"', '"reference": "Patient/mof-86"')

        # Replace Aidbox-proprietary Session references in AuditEvent with standard FHIR identifier/display
        res_str = re.sub(
            r'\{\s*"reference":\s*"Session/([^"]+)"\s*\}',
            r'{"identifier": {"system": "https://fhir.aidbox.app/Session", "value": "\1"}, "display": "Session/\1"}',
            res_str
        )

        clean_resource = json.loads(res_str)

        # Build clean transaction entry with PUT request
        new_entry = {
            "resource": clean_resource,
            "request": {
                "method": "PUT",
                "url": f"{resource_type}/{resource_id}"
            }
        }
        new_entries.append(new_entry)
        type_counts[resource_type] = type_counts.get(resource_type, 0) + 1

    transaction_bundle = {
        "resourceType": "Bundle",
        "type": "transaction",
        "entry": new_entries
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(transaction_bundle, f, indent=2)

    print(f"[+] Saved altered transaction bundle with {len(new_entries)} entries to {output_path}")
    print("[*] Resource breakdown in converted bundle:")
    for rt, cnt in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"    - {rt:24}: {cnt}")

    return transaction_bundle


def get_token(base_url: str, client_id: str, scope: str, verify_ssl: bool = False) -> str:
    """Fetch OAuth2 Bearer token using client_credentials grant."""
    token_url = f"{base_url.rstrip('/')}/fhir/auth/token"
    print(f"\n[*] Requesting access token from: {token_url}")
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "scope": scope
    }
    resp = requests.post(token_url, data=data, verify=verify_ssl, timeout=30)
    if resp.status_code != 200:
        fallback_url = f"{base_url.rstrip('/')}/auth/token"
        resp = requests.post(fallback_url, data=data, verify=verify_ssl, timeout=30)
    if resp.status_code != 200:
        raise RuntimeError(f"Token acquisition failed: {resp.status_code} - {resp.text}")

    token_json = resp.json()
    token = token_json.get("access_token")
    print(f"[+] Token acquired successfully (expires in: {token_json.get('expires_in')}s)")
    return token


def ensure_prerequisites(base_url: str, token: str, verify_ssl: bool = False):
    """Ensure prerequisite supporting resources (Practitioners, Locations, Organizations) exist on server."""
    fhir_endpoint = f"{base_url.rstrip('/')}/fhir"
    prereq_bundle = {
        "resourceType": "Bundle",
        "type": "transaction",
        "entry": [
            {
                "resource": r,
                "request": {"method": "PUT", "url": f"{r['resourceType']}/{r['id']}"}
            }
            for r in PREREQUISITE_SUPPORTING_RESOURCES
        ]
    }
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/fhir+json",
        "Accept": "application/fhir+json"
    }
    print(f"\n[*] Ensuring {len(PREREQUISITE_SUPPORTING_RESOURCES)} prerequisite supporting resources exist...")
    r = requests.post(fhir_endpoint, json=prereq_bundle, headers=headers, verify=verify_ssl, timeout=60)
    if r.status_code in (200, 201):
        print(f"[+] Prerequisite supporting resources are ready (HTTP {r.status_code}).")
    else:
        print(f"[!] Warning: Prerequisite creation returned HTTP {r.status_code}: {r.text[:300]}")


def import_transaction_bundle(base_url: str, token: str, bundle: dict, out_dir: Path, verify_ssl: bool = False):
    """Job 2: POST the transaction bundle to the FHIR endpoint and save individual outcome responses."""
    print(f"\n================================================================================")
    print(f"JOB 2: Importing Converted Transaction Bundle to {base_url}")
    print(f"================================================================================")
    fhir_endpoint = f"{base_url.rstrip('/')}/fhir"
    entry_count = len(bundle.get("entry", []))
    print(f"[*] Posting transaction bundle ({entry_count} resources) to: {fhir_endpoint}")

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/fhir+json",
        "Accept": "application/fhir+json"
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    start_time = time.time()
    resp = requests.post(
        fhir_endpoint,
        json=bundle,
        headers=headers,
        verify=verify_ssl,
        timeout=300
    )
    elapsed = round(time.time() - start_time, 2)
    print(f"[*] Server Response: HTTP {resp.status_code} ({elapsed} seconds)")

    try:
        resp_json = resp.json()
    except Exception:
        resp_json = {"raw_text": resp.text}

    # 1. Save full transaction response
    response_file = out_dir / "mof-85-transaction-bundle_response.json"
    with open(response_file, "w", encoding="utf-8") as rf:
        json.dump(resp_json, rf, indent=2)
    print(f"[+] Full transaction response saved to: {response_file.resolve()}")

    # 2. Extract itemized per-resource outcomes
    itemized_outcomes = []
    status_summary = {}

    if isinstance(resp_json, dict) and "entry" in resp_json:
        for idx, entry_resp in enumerate(resp_json.get("entry", [])):
            orig_entry = bundle["entry"][idx] if idx < len(bundle["entry"]) else {}
            orig_res = orig_entry.get("resource", {})
            rt = orig_res.get("resourceType", "Unknown")
            rid = orig_res.get("id", "Unknown")

            r_info = entry_resp.get("response", {})
            st = r_info.get("status", "")
            loc = r_info.get("location", "")
            etag = r_info.get("etag", "")

            status_summary[st] = status_summary.get(st, 0) + 1

            itemized_outcomes.append({
                "entry_index": idx,
                "resource_type": rt,
                "resource_id": rid,
                "http_status": st,
                "location": loc,
                "etag": etag
            })

    # Save itemized outcome report
    summary_file = out_dir / "mof-85_aidbox_imported_resources_summary.json"
    with open(summary_file, "w", encoding="utf-8") as sf:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "target_server": base_url,
            "total_submitted": entry_count,
            "http_response_code": resp.status_code,
            "elapsed_seconds": elapsed,
            "status_summary": status_summary,
            "resources": itemized_outcomes
        }, sf, indent=2)
    print(f"[+] Itemized resource import summary saved to: {summary_file.resolve()}")

    # Print summary
    print("\n" + "=" * 60)
    print("IMPORT STATUS SUMMARY")
    print("=" * 60)
    for st, cnt in sorted(status_summary.items()):
        print(f"  {st:25}: {cnt}")
    print(f"Total Resources Processed: {len(itemized_outcomes)} / {entry_count}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Convert Aidbox searchset bundle to transaction bundle and import.")
    parser.add_argument("--input", default=DEFAULT_INPUT_FILE, help=f"Input searchset JSON file (default: {DEFAULT_INPUT_FILE})")
    parser.add_argument("--output", default=DEFAULT_OUTPUT_FILE, help=f"Output transaction bundle file (default: {DEFAULT_OUTPUT_FILE})")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help=f"FHIR server base URL (default: {DEFAULT_BASE_URL})")
    parser.add_argument("--client-id", default=DEFAULT_CLIENT_ID, help=f"Registered SMART Client ID (default: {DEFAULT_CLIENT_ID})")
    parser.add_argument("--scope", default=DEFAULT_SCOPE, help=f"OAuth2 scope (default: {DEFAULT_SCOPE})")
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR, help=f"Outcome directory (default: {DEFAULT_OUT_DIR})")
    parser.add_argument("--convert-only", action="store_true", help="Only perform Job 1 (conversion) without importing")
    parser.add_argument("--strict-ssl", action="store_true", help="Enable strict SSL verification")

    args = parser.parse_args()

    input_path = Path(args.input).resolve()
    output_path = Path(args.output).resolve()
    out_dir = Path(args.out_dir).resolve()

    if not input_path.is_file():
        print(f"[-] Error: Input file not found: {input_path}")
        sys.exit(1)

    # Job 1: Convert
    transaction_bundle = convert_searchset_to_transaction_bundle(input_path, output_path)

    if args.convert_only:
        print("\n[+] Conversion completed. Skipping import (--convert-only flag was set).")
        return

    # Job 2: Import
    token = get_token(args.base_url, args.client_id, args.scope, verify_ssl=args.strict_ssl)
    ensure_prerequisites(args.base_url, token, verify_ssl=args.strict_ssl)
    import_transaction_bundle(args.base_url, token, transaction_bundle, out_dir, verify_ssl=args.strict_ssl)


if __name__ == "__main__":
    main()
