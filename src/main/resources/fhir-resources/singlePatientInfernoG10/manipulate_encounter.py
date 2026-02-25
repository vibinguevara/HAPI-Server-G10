import json
import os

def process_encounter_bundle(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # 1. Change bundle type to transaction
    data['type'] = 'transaction'
    
    # Remove top-level total and link
    if 'total' in data:
        del data['total']
    if 'link' in data:
        del data['link']

    # 2. Iterate through entries
    for entry in data.get('entry', []):
        if 'search' in entry:
            del entry['search']
        if 'fullUrl' in entry:
            del entry['fullUrl']
        if 'link' in entry:
            del entry['link']

        resource = entry.get('resource', {})
        resource_id = resource.get('id', '')

        entry['request'] = {
            "method": "PUT",
            "url": f"Encounter/{resource_id}"
        }

        # Update participant
        # Try to get period from existing participant or encounter
        period = {}
        if 'participant' in resource and isinstance(resource['participant'], list) and len(resource['participant']) > 0:
            if 'period' in resource['participant'][0]:
                period = resource['participant'][0]['period']
        if not period and 'period' in resource:
            period = resource['period']

        resource['participant'] = [{
            "type": [{
                "text": "primary performer",
                "coding": [{
                    "code": "PPRF",
                    "system": "http://terminology.hl7.org/CodeSystem/v3-ParticipationType",
                    "display": "primary performer"
                }]
            }],
            "period": period,
            "individual": {
                "reference": "Practitioner/c38e2d6b-b2d5-3f8e-acae-3044eeb5edbb"
            }
        }]
        
        # update location
        resource['location'] = [{
            "location": {
                "display": "LOWELL GENERAL HOSPITAL",
                "reference": "Location/8944e7cf-1482-b552-11a3-d3063d712d51"
            }
        }]

    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

if __name__ == '__main__':
    file_path = 'mof-85_EncounterResource.json'
    process_encounter_bundle(file_path)
    print("Encounter resource processed successfully.")
