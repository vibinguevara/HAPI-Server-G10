import requests
import json
import os

# Configuration
BASE_URL = "https://digressingly-auriferous-lee.ngrok-free.dev/fhir"
PATIENT_IDS = ["mof-85", "mof-86"]
OUTPUT_FILE = "src/main/resources/fhir-resources/singlePatientInfernoG10/mof-85_mof-86_Patient.json"

# You can either set the ACCESS_TOKEN environment variable or paste your token here
ACCESS_TOKEN = os.environ.get("ACCESS_TOKEN", "eyJraWQiOiJmZjA5MjhjMy1mZmExLTQ4NjQtOTAxZC03YThmMWMzZmIzYTMiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJQYXRpZW50L21vZi04NSIsImlkX3Rva2VuX3N1YiI6Im1vZi04NSIsInBhdGllbnQiOiJtb2YtODUiLCJzY29wZSI6ImxhdW5jaC9wYXRpZW50IG9wZW5pZCBmaGlyVXNlciBvZmZsaW5lX2FjY2VzcyBwYXRpZW50L01lZGljYXRpb24ucnMgcGF0aWVudC9BbGxlcmd5SW50b2xlcmFuY2UucnMgcGF0aWVudC9DYXJlUGxhbi5ycyBwYXRpZW50L0NhcmVUZWFtLnJzIHBhdGllbnQvQ29uZGl0aW9uLnJzIHBhdGllbnQvRGV2aWNlLnJzIHBhdGllbnQvRGlhZ25vc3RpY1JlcG9ydC5ycyBwYXRpZW50L0RvY3VtZW50UmVmZXJlbmNlLnJzIHBhdGllbnQvRW5jb3VudGVyLnJzIHBhdGllbnQvR29hbC5ycyBwYXRpZW50L0ltbXVuaXphdGlvbi5ycyBwYXRpZW50L0xvY2F0aW9uLnJzIHBhdGllbnQvTWVkaWNhdGlvblJlcXVlc3QucnMgcGF0aWVudC9PYnNlcnZhdGlvbi5ycyBwYXRpZW50L09yZ2FuaXphdGlvbi5ycyBwYXRpZW50L1BhdGllbnQucnMgcGF0aWVudC9QcmFjdGl0aW9uZXIucnMgcGF0aWVudC9Qcm9jZWR1cmUucnMgcGF0aWVudC9Qcm92ZW5hbmNlLnJzIHBhdGllbnQvUHJhY3RpdGlvbmVyUm9sZS5ycyBwYXRpZW50L1NlcnZpY2VSZXF1ZXN0LnJzIHBhdGllbnQvQ292ZXJhZ2UucnMgcGF0aWVudC9NZWRpY2F0aW9uRGlzcGVuc2UucnMgcGF0aWVudC9TcGVjaW1lbi5ycyBwYXRpZW50L1JlbGF0ZWRQZXJzb24ucnMiLCJpc3MiOiJodHRwczovL2RpZ3Jlc3NpbmdseS1hdXJpZmVyb3VzLWxlZS5uZ3Jvay1mcmVlLmRldi9maGlyIiwiZW5jb3VudGVyIjoiOGM0MmRlMDktMTBkOS00ZGZmLTgwNDItNzA4YTM4OTlhZTEwIiwiZXhwIjoxNzcyNDQ1MDYxLCJpYXQiOjE3NzI0NDQ3NjEsImZoaXJVc2VyIjoiaHR0cHM6Ly9kaWdyZXNzaW5nbHktYXVyaWZlcm91cy1sZWUubmdyb2stZnJlZS5kZXYvZmhpci9QcmFjdGl0aW9uZXIvYzM4ZTJkNmItYjJkNS0zZjhlLWFjYWUtMzA0NGVlYjVlZGJiIiwianRpIjoiNzhjZWY1ZjAtZDZlZC00NWU0LWJjNWQtN2Y3ZmJjYjA1YzU1In0.D-fCXoHdcyoo-sv5abRMFewBl1yA_ruqntKGFd8js_lzM0ebdKiEQHAtsN5bNIJ6j6ur1-cdykklofXqxUMU5upwGT4UlgEUP3ek83iHfjqfin3gQQnDzGMI_ikotLQY-x9k6mj0jchK6Zj0V4vmyce4jChOU9o-DiGvNo-I_LDAp1vcIc8TjRkbRDF8Y7CJMCXkZwKyndet0tT4iYMj0kRspZ-pMMF6SgAIZ0Pqck4Tv4owTjBsiOxjvZljmCH2Voq-QMSE_z-_DaffQfz3IfK-It4vmj_ShUSS1Z2-l-SHoxbzU9JLkPIMJ4NEqNlq73-yCot851qMSeBwWbadPQ")

def fetch_patient(patient_id, token):
    url = f"{BASE_URL}/Patient/{patient_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/fhir+json"
    }
    
    print(f"Fetching Patient/{patient_id}...")
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        print(f"Successfully retrieved Patient/{patient_id}")
        return response.json()
    else:
        print(f"Failed to retrieve Patient/{patient_id}. Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        return None

def main():
    if ACCESS_TOKEN == "eyJraWQiOiJmZjA5MjhjMy1mZmExLTQ4NjQtOTAxZC03YThmMWMzZmIzYTMiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJQYXRpZW50L21vZi04NSIsImlkX3Rva2VuX3N1YiI6Im1vZi04NSIsInBhdGllbnQiOiJtb2YtODUiLCJzY29wZSI6ImxhdW5jaC9wYXRpZW50IG9wZW5pZCBmaGlyVXNlciBvZmZsaW5lX2FjY2VzcyBwYXRpZW50L01lZGljYXRpb24ucnMgcGF0aWVudC9BbGxlcmd5SW50b2xlcmFuY2UucnMgcGF0aWVudC9DYXJlUGxhbi5ycyBwYXRpZW50L0NhcmVUZWFtLnJzIHBhdGllbnQvQ29uZGl0aW9uLnJzIHBhdGllbnQvRGV2aWNlLnJzIHBhdGllbnQvRGlhZ25vc3RpY1JlcG9ydC5ycyBwYXRpZW50L0RvY3VtZW50UmVmZXJlbmNlLnJzIHBhdGllbnQvRW5jb3VudGVyLnJzIHBhdGllbnQvR29hbC5ycyBwYXRpZW50L0ltbXVuaXphdGlvbi5ycyBwYXRpZW50L0xvY2F0aW9uLnJzIHBhdGllbnQvTWVkaWNhdGlvblJlcXVlc3QucnMgcGF0aWVudC9PYnNlcnZhdGlvbi5ycyBwYXRpZW50L09yZ2FuaXphdGlvbi5ycyBwYXRpZW50L1BhdGllbnQucnMgcGF0aWVudC9QcmFjdGl0aW9uZXIucnMgcGF0aWVudC9Qcm9jZWR1cmUucnMgcGF0aWVudC9Qcm92ZW5hbmNlLnJzIHBhdGllbnQvUHJhY3RpdGlvbmVyUm9sZS5ycyBwYXRpZW50L1NlcnZpY2VSZXF1ZXN0LnJzIHBhdGllbnQvQ292ZXJhZ2UucnMgcGF0aWVudC9NZWRpY2F0aW9uRGlzcGVuc2UucnMgcGF0aWVudC9TcGVjaW1lbi5ycyBwYXRpZW50L1JlbGF0ZWRQZXJzb24ucnMiLCJpc3MiOiJodHRwczovL2RpZ3Jlc3NpbmdseS1hdXJpZmVyb3VzLWxlZS5uZ3Jvay1mcmVlLmRldi9maGlyIiwiZW5jb3VudGVyIjoiOGM0MmRlMDktMTBkOS00ZGZmLTgwNDItNzA4YTM4OTlhZTEwIiwiZXhwIjoxNzcyNDQ1MDYxLCJpYXQiOjE3NzI0NDQ3NjEsImZoaXJVc2VyIjoiaHR0cHM6Ly9kaWdyZXNzaW5nbHktYXVyaWZlcm91cy1sZWUubmdyb2stZnJlZS5kZXYvZmhpci9QcmFjdGl0aW9uZXIvYzM4ZTJkNmItYjJkNS0zZjhlLWFjYWUtMzA0NGVlYjVlZGJiIiwianRpIjoiNzhjZWY1ZjAtZDZlZC00NWU0LWJjNWQtN2Y3ZmJjYjA1YzU1In0.D-fCXoHdcyoo-sv5abRMFewBl1yA_ruqntKGFd8js_lzM0ebdKiEQHAtsN5bNIJ6j6ur1-cdykklofXqxUMU5upwGT4UlgEUP3ek83iHfjqfin3gQQnDzGMI_ikotLQY-x9k6mj0jchK6Zj0V4vmyce4jChOU9o-DiGvNo-I_LDAp1vcIc8TjRkbRDF8Y7CJMCXkZwKyndet0tT4iYMj0kRspZ-pMMF6SgAIZ0Pqck4Tv4owTjBsiOxjvZljmCH2Voq-QMSE_z-_DaffQfz3IfK-It4vmj_ShUSS1Z2-l-SHoxbzU9JLkPIMJ4NEqNlq73-yCot851qMSeBwWbadPQ":
        print("WARNING: You must provide a valid ACCESS_TOKEN.")
        print("Please edit the script to add your token or set the ACCESS_TOKEN environment variable.")
        # Proceeding anyway as some servers might allow unauthenticated reads depending on config
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    
    bundle = {
        "resourceType": "Bundle",
        "type": "collection",
        "entry": []
    }
    
    for pid in PATIENT_IDS:
        patient_data = fetch_patient(pid, ACCESS_TOKEN)
        if patient_data:
            bundle["entry"].append({
                "resource": patient_data
            })
            
    # Write the combined results to the JSON file
    if bundle["entry"]:
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(bundle, f, indent=2)
        print(f"Successfully saved {len(bundle['entry'])} patients to {OUTPUT_FILE}")
    else:
        print("No patient data was retrieved. File not created.")

if __name__ == "__main__":
    main()
