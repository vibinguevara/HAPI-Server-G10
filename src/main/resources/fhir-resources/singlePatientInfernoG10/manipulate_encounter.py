import json
import os

file_path = r"c:\Labs\hwsafe\Analysis\sl-implementation-g10\hapi-fhir-jpaserver-starter-master\hapi-fhir-jpaserver-starter-master\src\main\resources\fhir-resources\singlePatientInfernoG10\mof-85_EncounterResource.json"

with open(file_path, 'r', encoding='utf-8') as f:
    data = json.load(f)

# Change bundle type to transaction to make it PUT friendly
if data.get('type') == 'searchset':
    data['type'] = 'transaction'

participant_block = [{
    "type": [{
        "text": "primary performer",
        "coding": [{
            "code": "PPRF",
            "system": "http://terminology.hl7.org/CodeSystem/v3-ParticipationType",
            "display": "primary performer"
        }]
    }],
    "period": {
        "end": "1941-05-15T19:48:18-04:00",
        "start": "1941-05-15T19:33:18-04:00"
    },
    "individual": {
        "reference": "Practitioner/c38e2d6b-b2d5-3f8e-acae-3044eeb5edbb"
    }
}]

for entry in data.get('entry', []):
    # Remove search, fullUrl, and link from each entry
    if 'search' in entry:
        del entry['search']
    if 'fullUrl' in entry:
        del entry['fullUrl']
    if 'link' in entry:
        del entry['link']
        
    resource = entry.get('resource', {})
    resource_id = resource.get('id', '')
    
    # Add PUT friendly request block
    if resource_id:
        entry['request'] = {
            "method": "PUT",
            "url": f"Encounter/{resource_id}"
        }
    
    # Remove location from each resource
    if 'location' in resource:
        del resource['location']
        
    # Replace participant array with the provided block
    resource['participant'] = participant_block

with open(file_path, 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=4)

print(f"Successfully modified {len(data.get('entry', []))} resources.")
