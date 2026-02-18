import urllib.request
import urllib.parse
import ssl
import json

BASE_URL = "https://localhost:8080"
NGROK_URL = "https://digressingly-auriferous-lee.ngrok-free.dev"
CAPABILITY_STATEMENT_FILE_PATH = r"C:/Labs/hwsafe/Analysis/sl-implementation-g10/hapi-fhir-jpaserver-starter-master/hapi-fhir-jpaserver-starter-master/src/main/resources/fhir-resources/us-core-capability-statement/CapabilityStatement-us-core-server.json"
OUTPUT_FILE = "capabilityStatement.json"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def import_capability_statement():
    print(f"Reading CapabilityStatement from {CAPABILITY_STATEMENT_FILE_PATH}...")
    try:
        with open(CAPABILITY_STATEMENT_FILE_PATH, 'r', encoding='utf-8') as f:
            cs_data = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    # Use the ID from the file or hardcoded 'us-core-server'
    resource_id = "us-core-server"
    fhir_url = f"{BASE_URL}/fhir/CapabilityStatement/{resource_id}"
    print(f"PUTting to {fhir_url}...")
    
    req = urllib.request.Request(fhir_url, data=cs_data.encode('utf-8'), method="PUT")
    req.add_header("Content-Type", "application/fhir+json")
    
    try:
        with urllib.request.urlopen(req, context=ctx) as response:
            status = response.status
            print(f"Import Success! Status: {status}")
            print(response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        print(f"HTTP Error during import: {e.code} {e.reason}")
        print(e.read().decode('utf-8'))
    except Exception as e:
        print(f"Exception during import: {e}")

def verify_metadata():
    metadata_url = f"{NGROK_URL}/fhir/metadata"
    print(f"\nFetching metadata from {metadata_url}...")
    
    try:
        req = urllib.request.Request(metadata_url, method="GET")
        req.add_header("Accept", "application/fhir+json")
        
        with urllib.request.urlopen(req, context=ctx) as response:
            status = response.status
            print(f"Metadata Fetch Success! Status: {status}")
            body = response.read().decode('utf-8')
            
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write(body)
            print(f"Metadata saved to {OUTPUT_FILE}")
            
    except urllib.error.HTTPError as e:
        print(f"HTTP Error during metadata fetch: {e.code} {e.reason}")
        print(e.read().decode('utf-8'))
    except Exception as e:
        print(f"Exception during metadata fetch: {e}")

if __name__ == "__main__":
    import_capability_statement()
    verify_metadata()
