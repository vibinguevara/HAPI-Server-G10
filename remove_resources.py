
import json
import shutil
import os

# Configuration
FILE_PATH = r"c:\Labs\hwsafe\Analysis\sl-implementation-g10\hapi-fhir-jpaserver-starter-master\hapi-fhir-jpaserver-starter-master\src\main\resources\fhir-resources\singlePatientInfernoG10\backup-3.json"
BACKUP_PATH = FILE_PATH + ".bak"
RESOURCES_TO_REMOVE = {'CareTeam', 'CarePlan', 'Immunization', 'AuditEvent'}

def main():
    if not os.path.exists(FILE_PATH):
        print(f"Error: File not found at {FILE_PATH}")
        return

    # Create backup
    print(f"Creating backup at {BACKUP_PATH}...")
    shutil.copy2(FILE_PATH, BACKUP_PATH)
    print("Backup created successfully.")

    # Read the file
    try:
        with open(FILE_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        return

    # Process the data
    # Assuming the structure is either a Bundle with 'entry' list or a list of resources
    # Most likely a Bundle based on the filename context, but handling both just in case
    
    removed_counts = {rtype: 0 for rtype in RESOURCES_TO_REMOVE}
    original_count = 0
    final_count = 0

    if isinstance(data, dict) and data.get('resourceType') == 'Bundle':
        print("Detected FHIR Bundle.")
        entries = data.get('entry', [])
        original_count = len(entries)
        new_entries = []
        
        for entry in entries:
            resource = entry.get('resource', {})
            resource_type = resource.get('resourceType')
            
            if resource_type in RESOURCES_TO_REMOVE:
                removed_counts[resource_type] += 1
            else:
                new_entries.append(entry)
        
        data['entry'] = new_entries
        final_count = len(new_entries)

    elif isinstance(data, list):
        print("Detected list of resources.")
        original_count = len(data)
        new_data = []
        
        for resource in data:
            resource_type = resource.get('resourceType')
            
            if resource_type in RESOURCES_TO_REMOVE:
                removed_counts[resource_type] += 1
            else:
                new_data.append(resource)
        
        data = new_data
        final_count = len(new_data)
        
    else:
        print("Unknown JSON structure. Expected Bundle or list of resources.")
        # If it's a single resource and matches the type, we might want to "empty" it or do nothing if it's the wrong type
        resource_type = data.get('resourceType')
        if resource_type in RESOURCES_TO_REMOVE:
             print(f"File contains a single resource of type {resource_type}. Cannot 'remove' from itself, please delete file if needed.")
             return
        else:
             print("File does not contain the targeted resources at top level.")
             return

    # Write back the modified data
    with open(FILE_PATH, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

    print("\nSummary of Removal:")
    for rtype, count in removed_counts.items():
        print(f"  {rtype}: {count}")
    
    print(f"\nOriginal Item Count: {original_count}")
    print(f"Final Item Count: {final_count}")
    print("Modification complete.")

if __name__ == "__main__":
    main()
