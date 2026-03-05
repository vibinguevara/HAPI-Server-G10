import requests
import argparse

# Default Revocation Endpoint URL
DEFAULT_URL = 'https://digressingly-auriferous-lee.ngrok-free.dev/fhir/auth/revoke'

def revoke_token(url, token=None, client_id=None, patient_id=None):
    print("Attempting to revoke tokens...")
    
    # We send parameters as form data to the endpoint
    data = {}
    if token:
        data['token'] = token
    if client_id:
        data['client_id'] = client_id
    if patient_id:
        data['patient_id'] = patient_id
        
    if not data:
        print("Error: No parameters provided for revocation (token, client_id, or patient_id).")
        return
        
    print(f"Sending parameters: {data}")
    print(f"To endpoint: {url}")
    
    try:
        response = requests.post(url, data=data)
        
        # Check if the request was successful
        if response.status_code == 200:
            print("Successfully called the revocation endpoint. Tokens matching the criteria (if any) should be revoked.")
            print(f"Server Response Headers: {response.headers}")
            print(f"Server Response Body: {response.text}")
        else:
            print(f"Failed to call revocation endpoint. Status Code: {response.status_code}")
            print(f"Response: {response.text}")
            
    except requests.exceptions.RequestException as e:
        print(f"Error calling the endpoint: {e}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Test token revocation endpoint")
    parser.add_argument('--url', type=str, default=DEFAULT_URL, help="Revocation endpoint URL")
    parser.add_argument('--token', type=str, help="Token to revoke")
    parser.add_argument('--client_id', type=str, help="Client ID associated with the token(s) to revoke")
    parser.add_argument('--patient_id', type=str, help="Patient ID associated with the token(s) to revoke")
    
    args = parser.parse_args([
    '--url', 'https://digressingly-auriferous-lee.ngrok-free.dev/fhir/auth/revoke',
    '--token', 'eyJraWQiOiI2OTIxNDdmNi02YWFmLTQxNjEtOTkxMC1iZmJmNzM2MWQwMTIiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJQYXRpZW50L21vZi04NSIsImlkX3Rva2VuX3N1YiI6Im1vZi04NSIsInBhdGllbnQiOiJtb2YtODUiLCJzY29wZSI6ImxhdW5jaCBvcGVuaWQgZmhpclVzZXIgb2ZmbGluZV9hY2Nlc3MgdXNlci9NZWRpY2F0aW9uLnJzIHVzZXIvQWxsZXJneUludG9sZXJhbmNlLnJzIHVzZXIvQ2FyZVBsYW4ucnMgdXNlci9DYXJlVGVhbS5ycyB1c2VyL0NvbmRpdGlvbi5ycyB1c2VyL0RldmljZS5ycyB1c2VyL0RpYWdub3N0aWNSZXBvcnQucnMgdXNlci9Eb2N1bWVudFJlZmVyZW5jZS5ycyB1c2VyL0VuY291bnRlci5ycyB1c2VyL0dvYWwucnMgdXNlci9JbW11bml6YXRpb24ucnMgdXNlci9Mb2NhdGlvbi5ycyB1c2VyL01lZGljYXRpb25SZXF1ZXN0LnJzIHVzZXIvT2JzZXJ2YXRpb24ucnMgdXNlci9Pcmdhbml6YXRpb24ucnMgdXNlci9QYXRpZW50LnJzIHVzZXIvUHJhY3RpdGlvbmVyLnJzIHVzZXIvUHJvY2VkdXJlLnJzIHVzZXIvUHJvdmVuYW5jZS5ycyB1c2VyL1ByYWN0aXRpb25lclJvbGUucnMgdXNlci9TZXJ2aWNlUmVxdWVzdC5ycyB1c2VyL0NvdmVyYWdlLnJzIHVzZXIvTWVkaWNhdGlvbkRpc3BlbnNlLnJzIHVzZXIvU3BlY2ltZW4ucnMgdXNlci9SZWxhdGVkUGVyc29uLnJzIiwiaXNzIjoiaHR0cHM6Ly9kaWdyZXNzaW5nbHktYXVyaWZlcm91cy1sZWUubmdyb2stZnJlZS5kZXYvZmhpciIsImVuY291bnRlciI6IjdjMTNhZDcxLTk0YjAtODNlNC1kYjU3LTFiNDY2ZjgxNDBjMCIsImV4cCI6MTc3MjY4NzgwOCwiaWF0IjoxNzcyNjg3NTA4LCJmaGlyVXNlciI6Imh0dHBzOi8vZGlncmVzc2luZ2x5LWF1cmlmZXJvdXMtbGVlLm5ncm9rLWZyZWUuZGV2L2ZoaXIvUHJhY3RpdGlvbmVyL2MzOGUyZDZiLWIyZDUtM2Y4ZS1hY2FlLTMwNDRlZWI1ZWRiYiIsImp0aSI6IjhjZjhmOWEyLWQzNjktNGUyYi1iMzA3LWU0MWE1OTU4YjVlYSJ9.W2DPsJxFyP0HeZrRiZEmy9aeErxXKKjBv_GFtVVDz2leX7Qwmw-ZLAyJUuSxt_PRNcdPKlx3T7ehBWN5iTr79Y5WcJuhs2rqphzMj-XES2ayL5PiJPHkjedRfGGYbcTr9QwlO5sf9DVvphGncMI_1hJJTfwqeX0AOzPKRzvnx5TAAn02tTnDLErrYns9ZU_wvSCoZipP_APTmvCm12XVWxEWQPpGcRd1QNhfUbDq0Qa4kNMF9W0DziWhYl_-xzQfAdOD6Y8yK7RRY_jOz1k6kNNobnQGAi-8SsxyZZ3gkQQmxGn2bGcuLpnQZNLr-5bs1FBDVpi_DAnp_UsM1oUnjg',
    '--client_id', 'tdavis751076',
    '--patient_id', 'mof-85'
])
    
    revoke_token(args.url, args.token, args.client_id, args.patient_id)
