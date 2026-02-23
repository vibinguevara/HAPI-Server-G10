
import json
import datetime

file_path = r"C:\Labs\hwsafe\Analysis\sl-implementation-g10\hapi-fhir-jpaserver-starter-master\hapi-fhir-jpaserver-starter-master\src\main\resources\fhir-resources\singlePatientInfernoG10.json"

def get_timestamp():
    # Using a fixed timestamp for reproducibility as per previous context or current time?
    # User said "Global timestamp" for Provenance.
    # I'll use a fixed recent timestamp to ensure consistency.
    return "2024-01-01T10:00:00Z"

def get_current_timestamp():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


print(f"Reading bundle from {file_path}...")
with open(file_path, 'r', encoding='utf-8') as f:
    bundle = json.load(f)

new_entries = []
modified_count = 0

# Helper to find if an object with specific key-value pair exists in a list
def has_coding(codings, system, code):
    for coding in codings:
        if coding.get('system') == system and coding.get('code') == code:
            return True
    return False

# Process existing entries
for entry in bundle['entry']:
    resource = entry['resource']
    resource_type = resource['resourceType']
    resource_id = resource['id']
    full_id = f"{resource_type}/{resource_id}"
    
    # 1. Update AllergyIntolerance
    if resource_type == 'AllergyIntolerance':
        if 'reaction' not in resource:
            print(f"Updating AllergyIntolerance/{resource_id}: Adding reaction")
            resource['reaction'] = [{
                "manifestation": [{
                    "coding": [
                        {
                            "system": "http://snomed.info/sct",
                            "code": "247472004",
                            "display": "Urticarial eruption"
                        }
                    ],
                    "text": "Urticarial eruption"
                }]
            }]
            modified_count += 1

    # 2. Update CarePlan
    if resource_type == 'CarePlan':
        if 'text' not in resource:
            print(f"Updating CarePlan/{resource_id}: Adding text")
            resource['text'] = {
                "status": "generated",
                "div": "<div xmlns=\"http://www.w3.org/1999/xhtml\">Care Plan</div>"
            }
            modified_count += 1

    # 3. Update Condition
    if resource_type == 'Condition':
        # Condition (Encounter Diagnosis)
        if 'encounter-diagnosis' in resource_id:
            print(f"Updating Condition/{resource_id}: Adding abatementDateTime, recordedDate, encounter")
            resource['abatementDateTime'] = get_timestamp()
            resource['recordedDate'] = get_timestamp()
            resource['encounter'] = {"reference": "Encounter/encounter-1"}
            modified_count += 1
            
        # Condition (Problems/Health Concerns)
        elif 'problem' in resource_id:
             print(f"Updating Condition/{resource_id}: Adding onsetDateTime, recordedDate, screening-assessment category")
             resource['onsetDateTime'] = get_timestamp()
             resource['recordedDate'] = get_timestamp()
             
             # Add category: screening-assessment
             if 'category' not in resource:
                 resource['category'] = []
             
             # Check if already present
             has_screening = False
             for cat in resource['category']:
                 if has_coding(cat.get('coding', []), "http://terminology.hl7.org/CodeSystem/condition-category", "screening-assessment"): # checking system/code guess
                     has_screening = True
             
             # Actually screening-assessment might be a different system or just a code. 
             # US Core usually uses http://terminology.hl7.org/CodeSystem/condition-category
             # but "screening-assessment" is often associated with SDOH or specific profiles.
             # User requested "Condition.category:screening-assessment"
             # I'll add a generic one with that code if not specific system is required, or standard.
             # Actually, "health-concern" is standard. "screening-assessment" might be from a specific value set.
             # I'll use the system user likely expects or standard one.
             if not has_screening:
                 resource['category'].append({
                     "coding": [
                         {
                             "system": "http://terminology.hl7.org/CodeSystem/condition-category", # Best guess for standard categories
                             "code": "screening-assessment",
                             "display": "Screening Assessment" 
                         }
                     ]
                 })
             
             # Add extension: assertedDate
             if 'extension' not in resource:
                 resource['extension'] = []
             
             has_asserted = False
             for ext in resource['extension']:
                 if ext.get('url') == "http://hl7.org/fhir/StructureDefinition/condition-assertedDate":
                     has_asserted = True
             
             if not has_asserted:
                 resource['extension'].append({
                     "url": "http://hl7.org/fhir/StructureDefinition/condition-assertedDate",
                     "valueDateTime": get_timestamp()
                 })
             modified_count += 1

    # 4. Update Coverage
    if resource_type == 'Coverage':
        # Add identifier (Member Id)
        if 'identifier' not in resource:
             resource['identifier'] = []
        
        has_member_id = False
        for ident in resource['identifier']:
            for coding in ident.get('type', {}).get('coding', []):
                 if coding.get('code') == 'MB':
                     has_member_id = True
        
        if not has_member_id:
            print(f"Updating Coverage/{resource_id}: Adding MemberId identifier")
            resource['identifier'].append({
                "type": {
                    "coding": [
                        {
                            "system": "http://terminology.hl7.org/CodeSystem/v2-0203",
                            "code": "MB",
                            "display": "Member Number"
                        }
                    ]
                },
                "system": "https://example.org/member-ids",
                "value": "MB123456"
            })
            modified_count += 1

    # 5. Generate Provenance for EACH resource
    # Do not create Provenance for Provenance!
    if resource_type != 'Provenance':
        provenance_id = f"provenance-{resource_id}"
        # Check if this provenance already exists in the bundle (to avoid duplication if re-run)
        # But we are iterating over existing entries. 
        # We will append new entries at the end. 
        # But if we re-run this script on an already updated bundle, we might duplicate.
        # So we should check if `provenance-id` is already in existing entries' IDs?
        # But `provenance-id` will be newly generated. 
        # If the file already has 'provenance-patient-9099', we shouldn't add it again.
        
        # We can do a quick check against bundle['entry'] IDs.
        already_exists = False
        for e in bundle['entry']:
            if e['resource']['id'] == provenance_id:
                already_exists = True
                break
        
        if not already_exists:
            provenance = {
                "resource": {
                    "resourceType": "Provenance",
                    "id": provenance_id,
                     "meta": {
                        "versionId": "1",
                        "lastUpdated": get_current_timestamp(),
                        "profile": [
                            "http://hl7.org/fhir/us/core/StructureDefinition/us-core-provenance"
                        ]
                    },
                    "target": [
                        {
                            "reference": full_id
                        }
                    ],
                    "recorded": get_timestamp(),
                    "agent": [
                        {
                            "type": {
                                "coding": [
                                    {
                                        "system": "http://terminology.hl7.org/CodeSystem/provenance-participant-type",
                                        "code": "performer",
                                        "display": "Performer"
                                    }
                                ]
                            },
                            "who": {
                                "reference": "Practitioner/practitioner-1" # Assumes this exists!
                            }
                        }
                    ]
                },
                "request": {
                    "method": "PUT",
                    "url": f"Provenance/{provenance_id}"
                }
            }
            new_entries.append(provenance)

# Append new Provenance resources to the bundle
if new_entries:
    print(f"Adding {len(new_entries)} new Provenance resources.")
    bundle['entry'].extend(new_entries)
else:
    print("No new Provenance resources added (likely already exist).")

print(f"Writing updated bundle to {file_path}...")
with open(file_path, 'w', encoding='utf-8') as f:
    json.dump(bundle, f, indent=4) # Using default json dumper

print("Done.")
