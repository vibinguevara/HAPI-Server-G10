#!/usr/bin/env python3
"""
Import all clinical and supporting resources for Patient mof-85 into FHIR Server.

This script:
1. Connects to SMART on FHIR backend using OAuth2 'client_credentials' grant with Client ID 685fb6bb-831c-4335-ac1a-3ddb1aec016d.
2. Identifies all relevant transaction bundle files in singlePatientInfernoG10, excluding non-relevant/backup files.
3. Orders bundles to respect FHIR reference dependencies (Organizations -> Practitioners -> Locations -> Encounters -> Clinical resources).
4. Submits each transaction bundle via POST /fhir.
5. Writes the exact HTTP outcome response for each bundle into a separate JSON file in --out-dir.
6. Emits a consolidated summary report (JSON and CLI table).
"""

import argparse
import json
import os
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
DEFAULT_OUT_DIR = "import_outcomes"

EXCLUDED_FILES = {
    "mof-85_Patient.json",
    "mof-85_mof-86_Patient.json",
    "backup.json",
    "backup-2.json",
    "backup-3.json",
    "backup-3.json.bak",
    "endpointResource.json",
    "manipulate_encounter.py",
    "manipulate_observation.py",
    "service-url-fhir.json",
    "single_patient_85_aidbox_resource.json",
    "single_patient_fhir_85_write.json",
    "singlePatientInfernoG10.json",
    "provenance_fhir_bundle.json",
    "multi_patient_86_aidbox_resource.json",
}

# Preferred dependency order for importing bundles
DEPENDENCY_ORDER_PRIORITY = {
    # 1. Infrastructure / Foundation
    "mof-85_Organization.json": 10,
    "mof-85_Practitioner.json": 20,
    "mof-85_LocationResource.json": 30,
    
    # 2. Encounters (Visits)
    "mof-85_EncounterResource.json": 40,
    "mof-85_EncounterResourceBundle-Backup.json": 45,
    
    # 3. Clinical Conditions
    "mof-85_condition_granular_scope-1.json": 50,
    "mof-85_ScreeningAssessmentGuidance.json": 55,
    
    # 4. Clinical Observations & Tests
    "mof-85_ObservationBloodPressureTest.json": 60,
    "mof-85_ObservationBodyHeightTest.json": 61,
    "mof-85_ObservationPulseOximetryTest.json": 62,
    "mof-85_ObservationLaboratoryResults.json": 63,
    "mof-85_ObservationOccupatientTest.json": 64,
    "mof-85_ObservationPregnancyIntent.json": 65,
    "mof-85_ObservationPregnancyStatus.json": 66,
    "mof-85_ObservationScreeningAssessmentTest.json": 67,
    
    # 5. Diagnostic Reports & Documents
    "mof-85_DiagnosticReportResource.json": 70,
    "mof-85_DocumentReferenceResource.json": 75,
    
    # 6. Procedures
    "mof-85_Procedure.json": 80,
    
    # 7. Medications
    "mof-85_MedicationRequests.json": 90,
    "mof-85_MedicationDispense.json": 95,
    
    # 8. Devices & Service Requests
    "mof-85_DeviceImplantation.json": 100,
    "mof-85_ServiceRequest.json": 105,
}

class TokenManager:
    """Manages acquisition and automatic refresh of SMART OAuth2 tokens."""
    def __init__(self, base_url: str, client_id: str, scope: str, verify_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.scope = scope
        self.verify_ssl = verify_ssl
        self.access_token = None
        self.expires_at = 0

    def get_token(self) -> str:
        # Refresh if token expires in less than 45 seconds
        if self.access_token and time.time() < (self.expires_at - 45):
            return self.access_token

        token_url = f"{self.base_url}/fhir/auth/token"
        print(f"\n[*] Requesting SMART OAuth2 access token from: {token_url}")
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "scope": self.scope
        }

        try:
            resp = requests.post(token_url, data=data, verify=self.verify_ssl, timeout=30)
        except Exception as e:
            fallback_url = f"{self.base_url}/auth/token"
            print(f"[!] Primary token endpoint failed ({e}), trying: {fallback_url}")
            resp = requests.post(fallback_url, data=data, verify=self.verify_ssl, timeout=30)

        if resp.status_code != 200:
            raise RuntimeError(f"Token request failed with status {resp.status_code}: {resp.text}")

        token_json = resp.json()
        self.access_token = token_json.get("access_token")
        expires_in = token_json.get("expires_in", 300)
        self.expires_at = time.time() + expires_in

        print(f"[+] Token acquired successfully (expires in: {expires_in}s, scope: {token_json.get('scope')})")
        return self.access_token


def locate_resource_dir(custom_path: str = None) -> Path:
    """Locate the singlePatientInfernoG10 directory."""
    if custom_path and os.path.exists(custom_path):
        return Path(custom_path).resolve()

    candidates = [
        "src/main/resources/fhir-resources/singlePatientInfernoG10",
        "src/main/resources/SinglePatientInfernoG10",
        "fhir-resources/singlePatientInfernoG10",
        "singlePatientInfernoG10"
    ]

    for c in candidates:
        p = Path.cwd() / c
        if p.is_dir():
            return p.resolve()

    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent
    for c in candidates:
        p = repo_root / c
        if p.is_dir():
            return p.resolve()

    raise FileNotFoundError("Could not find singlePatientInfernoG10 resource directory.")


def get_bundle_files(resource_dir: Path) -> list[Path]:
    """Identify candidate bundle JSON files to import, ordered by dependency."""
    all_files = [f for f in resource_dir.iterdir() if f.is_file() and f.suffix.lower() == ".json"]
    
    candidate_files = []
    for f in all_files:
        if f.name in EXCLUDED_FILES:
            continue
        candidate_files.append(f)

    # Sort files according to DEPENDENCY_ORDER_PRIORITY (defaults to 999 if not specifically mapped)
    candidate_files.sort(key=lambda f: (DEPENDENCY_ORDER_PRIORITY.get(f.name, 999), f.name))
    return candidate_files


def import_bundles(base_url: str, client_id: str, scope: str, resource_dir: Path, out_dir: Path, dry_run: bool = False, verify_ssl: bool = False):
    """Import all candidate bundles and write individual outcomes to disk."""
    out_dir.mkdir(parents=True, exist_ok=True)
    bundle_files = get_bundle_files(resource_dir)

    print("================================================================================")
    print("FHIR Single-Patient (mof-85) Resource Importer")
    print("================================================================================")
    print(f"Target Server   : {base_url}")
    print(f"FHIR Endpoint   : {base_url.rstrip('/')}/fhir")
    print(f"Client ID       : {client_id}")
    print(f"Scope           : {scope}")
    print(f"Resource Dir    : {resource_dir}")
    print(f"Outcome Dir     : {out_dir.resolve()}")
    print(f"Bundles to post : {len(bundle_files)}")
    print("================================================================================")

    if dry_run:
        print("\n[DRY RUN MODE] The following bundles would be posted in this order:")
        for idx, f in enumerate(bundle_files, 1):
            with open(f, 'r', encoding='utf-8') as jf:
                d = json.load(jf)
                cnt = len(d.get("entry", []))
                rt = d.get("entry", [{}])[0].get("resource", {}).get("resourceType", "Unknown") if cnt else "Empty"
            print(f"  {idx:2d}. {f.name:45} (Entries: {cnt:3d}, Primary Type: {rt})")
        return

    token_mgr = TokenManager(base_url, client_id, scope, verify_ssl=verify_ssl)
    fhir_endpoint = f"{base_url.rstrip('/')}/fhir"

    summary_records = []
    total_resources_posted = 0
    total_resources_succeeded = 0

    start_all = time.time()

    for idx, bundle_path in enumerate(bundle_files, 1):
        print(f"\n[{idx}/{len(bundle_files)}] Processing {bundle_path.name}...")

        with open(bundle_path, "r", encoding="utf-8") as f:
            bundle_json = json.load(f)

        entries = bundle_json.get("entry", [])
        entry_count = len(entries)
        resource_types = sorted(list(set(e.get("resource", {}).get("resourceType", "Unknown") for e in entries)))
        resource_types_str = ", ".join(resource_types)

        print(f"    - Resource Types: {resource_types_str}")
        print(f"    - Total Entries : {entry_count}")

        token = token_mgr.get_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/fhir+json",
            "Accept": "application/fhir+json"
        }

        req_time = datetime.now().isoformat()
        start_post = time.time()

        try:
            res = requests.post(
                fhir_endpoint,
                json=bundle_json,
                headers=headers,
                verify=verify_ssl,
                timeout=120
            )
            elapsed = round(time.time() - start_post, 2)
            status_code = res.status_code
            print(f"    - HTTP Status   : {status_code} ({elapsed}s)")

            try:
                resp_json = res.json()
            except Exception:
                resp_json = {"raw_text": res.text}

            # Evaluate success details
            success_count = 0
            error_count = 0
            entry_outcomes = []

            if isinstance(resp_json, dict) and "entry" in resp_json:
                for e_idx, e in enumerate(resp_json.get("entry", [])):
                    r = e.get("response", {})
                    st = r.get("status", "")
                    loc = r.get("location", "")
                    is_ok = any(code in st for code in ["200", "201", "204"])
                    if is_ok:
                        success_count += 1
                    else:
                        error_count += 1
                    entry_outcomes.append({
                        "entry_index": e_idx,
                        "status": st,
                        "location": loc,
                        "outcome": r.get("outcome")
                    })
            elif status_code in (200, 201):
                success_count = entry_count
            else:
                error_count = entry_count

            # Write individual outcome file
            outcome_data = {
                "bundle_file": bundle_path.name,
                "timestamp": req_time,
                "elapsed_seconds": elapsed,
                "http_status_code": status_code,
                "entries_submitted": entry_count,
                "entries_succeeded": success_count,
                "entries_failed": error_count,
                "resource_types": resource_types,
                "response": resp_json
            }

            safe_stem = bundle_path.stem
            outcome_file = out_dir / f"{safe_stem}_outcome.json"
            with open(outcome_file, "w", encoding="utf-8") as out_f:
                json.dump(outcome_data, out_f, indent=2)

            print(f"    - Outcome Saved : {outcome_file.name} (Success: {success_count}/{entry_count})")

            total_resources_posted += entry_count
            total_resources_succeeded += success_count

            summary_records.append({
                "file": bundle_path.name,
                "resource_types": resource_types_str,
                "entries": entry_count,
                "status_code": status_code,
                "succeeded": success_count,
                "failed": error_count,
                "elapsed_s": elapsed,
                "outcome_file": str(outcome_file.name)
            })

        except Exception as ex:
            elapsed = round(time.time() - start_post, 2)
            print(f"    - [ERROR] Post failed: {ex}")
            err_data = {
                "bundle_file": bundle_path.name,
                "timestamp": req_time,
                "elapsed_seconds": elapsed,
                "error": str(ex)
            }
            outcome_file = out_dir / f"{bundle_path.stem}_error.json"
            with open(outcome_file, "w", encoding="utf-8") as out_f:
                json.dump(err_data, out_f, indent=2)

            summary_records.append({
                "file": bundle_path.name,
                "resource_types": resource_types_str,
                "entries": entry_count,
                "status_code": "ERROR",
                "succeeded": 0,
                "failed": entry_count,
                "elapsed_s": elapsed,
                "outcome_file": str(outcome_file.name)
            })

    total_time = round(time.time() - start_all, 2)

    # Write Master Summary JSON
    master_summary = {
        "server": base_url,
        "client_id": client_id,
        "scope": scope,
        "timestamp": datetime.now().isoformat(),
        "total_bundles_processed": len(bundle_files),
        "total_resources_submitted": total_resources_posted,
        "total_resources_succeeded": total_resources_succeeded,
        "total_duration_seconds": total_time,
        "bundles": summary_records
    }

    summary_file = out_dir / "summary_report.json"
    with open(summary_file, "w", encoding="utf-8") as sf:
        json.dump(master_summary, sf, indent=2)

    # Print Final Summary Table
    print("\n" + "=" * 92)
    print("IMPORT COMPLETE - SUMMARY REPORT")
    print("=" * 92)
    header = f"{'#':<3} {'Bundle File':<42} {'Types':<20} {'Submitted':<10} {'Status':<7} {'Success':<8}"
    print(header)
    print("-" * 92)
    for i, rec in enumerate(summary_records, 1):
        st_val = str(rec['status_code'])
        print(f"{i:<3} {rec['file']:<42} {rec['resource_types'][:19]:<20} {rec['entries']:<10} {st_val:<7} {rec['succeeded']:<8}")
    print("-" * 92)
    print(f"Totals: {len(summary_records)} bundles | {total_resources_succeeded}/{total_resources_posted} resources succeeded ({total_time}s)")
    print(f"Detailed outcome files saved in : {out_dir.resolve()}")
    print(f"Master summary report saved in  : {summary_file.resolve()}")
    print("=" * 92)


def main():
    parser = argparse.ArgumentParser(description="Import Patient mof-85 clinical bundles into FHIR server.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help=f"FHIR server base URL (default: {DEFAULT_BASE_URL})")
    parser.add_argument("--client-id", default=DEFAULT_CLIENT_ID, help=f"Registered SMART Client ID (default: {DEFAULT_CLIENT_ID})")
    parser.add_argument("--scope", default=DEFAULT_SCOPE, help=f"OAuth2 scope to request (default: {DEFAULT_SCOPE})")
    parser.add_argument("--dir", default=None, help="Directory containing bundle JSON files")
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR, help=f"Directory to save outcome JSON files (default: {DEFAULT_OUT_DIR})")
    parser.add_argument("--dry-run", action="store_true", help="Print plan without sending HTTP requests")
    parser.add_argument("--strict-ssl", action="store_true", help="Enable strict SSL verification")

    args = parser.parse_args()

    resource_dir = locate_resource_dir(args.dir)
    out_dir = Path(args.out_dir)

    import_bundles(
        base_url=args.base_url,
        client_id=args.client_id,
        scope=args.scope,
        resource_dir=resource_dir,
        out_dir=out_dir,
        dry_run=args.dry_run,
        verify_ssl=args.strict_ssl
    )

if __name__ == "__main__":
    main()
