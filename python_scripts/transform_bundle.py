import json
import os

# Configuration
SOURCE_DIR = r"c:\Labs\hwsafe\Analysis\sl-implementation-g10\hapi-fhir-jpaserver-starter-master\hapi-fhir-jpaserver-starter-master\src\main\resources\fhir-resources\singlePatientInfernoG10"
INPUT_FILE = "single_patient_85_aidbox_resource.json"
OUTPUT_FILE = "single_patient_fhir_85_write.json"

def transform_bundle():
    input_path = os.path.join(SOURCE_DIR, INPUT_FILE)
    output_path = os.path.join(SOURCE_DIR, OUTPUT_FILE)

    if not os.path.exists(input_path):
        print(f"Error: Input file not found at {input_path}")
        return

    print(f"Reading {input_path}...")
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            bundle = json.load(f)
    except Exception as e:
        print(f"Error reading JSON: {e}")
        return

    # Transformation
    new_bundle = {
        "resourceType": "Bundle",
        "type": "transaction",
        "entry": []
    }

    if "entry" not in bundle:
        print("Warning: No 'entry' field found in input bundle.")

    for entry in bundle.get("entry", []):
        resource = entry.get("resource")
        if not resource:
            continue

        resource_type = resource.get("resourceType")
        resource_id = resource.get("id")

        if not resource_type or not resource_id:
            print(f"Skipping resource without type or id: {resource}")
            continue

        # Create new entry structure
        new_entry = {
            "resource": resource,
            "request": {
                "method": "PUT",
                "url": f"{resource_type}/{resource_id}"
            }
        }
        
        # Remove unwanted fields from previous entry wrapper if they existed
        # (Actually we are building new_entry from scratch, so search/link/fullUrl are naturally excluded unless we add them)
        
        # Ensure resource itself doesn't have unwanted fields if that was the requirement?
        # User said "remove search, link and fullUrl". These are usually on the entry, not the resource.
        # But if they are on the resource (rare), we might want to check.
        # The user's example shows "resource": { ... }, "request": { ... }.
        # So we just take the 'resource' object as is.
        
        new_bundle["entry"].append(new_entry)

    print(f"Transformed {len(new_bundle['entry'])} entries.")

    print(f"Writing to {output_path}...")
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(new_bundle, f, indent=2)
        print("Success.")
    except Exception as e:
        print(f"Error writing file: {e}")

if __name__ == "__main__":
    transform_bundle()
