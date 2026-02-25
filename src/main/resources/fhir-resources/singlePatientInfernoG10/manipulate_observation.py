import json
import os

file_path = r"c:\Labs\hwsafe\Analysis\sl-implementation-g10\hapi-fhir-jpaserver-starter-master\hapi-fhir-jpaserver-starter-master\src\main\resources\fhir-resources\singlePatientInfernoG10\mof-85_ObservationLaboratoryResults.json"

with open(file_path, 'r', encoding='utf-8') as f:
    data = json.load(f)

# Change bundle type to transaction to make it PUT friendly
if data.get('type') == 'searchset':
    data['type'] = 'transaction'

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
            "url": f"Observation/{resource_id}"
        }

with open(file_path, 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=4)

print(f"Successfully modified {len(data.get('entry', []))} resources.")
