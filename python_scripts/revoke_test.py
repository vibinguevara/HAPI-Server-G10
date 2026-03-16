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
    '--token', 'eyJraWQiOiJlMDI0ZDRiMi04YWQ1LTQyOWEtOWRjMC03YjFkZmQ2ZjI5ZTciLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJQYXRpZW50L21vZi04NSIsImlkX3Rva2VuX3N1YiI6Im1vZi04NSIsInBhdGllbnQiOiJtb2YtODUiLCJzY29wZSI6ImxhdW5jaCBvcGVuaWQgZmhpclVzZXIgb2ZmbGluZV9hY2Nlc3MgdXNlci9NZWRpY2F0aW9uLnJzIHVzZXIvQWxsZXJneUludG9sZXJhbmNlLnJzIHVzZXIvQ2FyZVBsYW4ucnMgdXNlci9DYXJlVGVhbS5ycyB1c2VyL0NvbmRpdGlvbi5ycyB1c2VyL0RldmljZS5ycyB1c2VyL0RpYWdub3N0aWNSZXBvcnQucnMgdXNlci9Eb2N1bWVudFJlZmVyZW5jZS5ycyB1c2VyL0VuY291bnRlci5ycyB1c2VyL0dvYWwucnMgdXNlci9JbW11bml6YXRpb24ucnMgdXNlci9Mb2NhdGlvbi5ycyB1c2VyL01lZGljYXRpb25SZXF1ZXN0LnJzIHVzZXIvT2JzZXJ2YXRpb24ucnMgdXNlci9Pcmdhbml6YXRpb24ucnMgdXNlci9QYXRpZW50LnJzIHVzZXIvUHJhY3RpdGlvbmVyLnJzIHVzZXIvUHJvY2VkdXJlLnJzIHVzZXIvUHJvdmVuYW5jZS5ycyB1c2VyL1ByYWN0aXRpb25lclJvbGUucnMgdXNlci9TZXJ2aWNlUmVxdWVzdC5ycyB1c2VyL0NvdmVyYWdlLnJzIHVzZXIvTWVkaWNhdGlvbkRpc3BlbnNlLnJzIHVzZXIvU3BlY2ltZW4ucnMgdXNlci9SZWxhdGVkUGVyc29uLnJzIiwiaXNzIjoiaHR0cHM6Ly9kaWdyZXNzaW5nbHktYXVyaWZlcm91cy1sZWUubmdyb2stZnJlZS5kZXYvZmhpciIsImVuY291bnRlciI6IjdjMTNhZDcxLTk0YjAtODNlNC1kYjU3LTFiNDY2ZjgxNDBjMCIsImV4cCI6MTc3MzE2MTI1NiwiaWF0IjoxNzczMTYwOTU2LCJmaGlyVXNlciI6Imh0dHBzOi8vZGlncmVzc2luZ2x5LWF1cmlmZXJvdXMtbGVlLm5ncm9rLWZyZWUuZGV2L2ZoaXIvUHJhY3RpdGlvbmVyL2MzOGUyZDZiLWIyZDUtM2Y4ZS1hY2FlLTMwNDRlZWI1ZWRiYiIsImp0aSI6ImRhZGI4YzYyLWFjZjUtNGZlMi05NTA4LWZiMGJhYTk0ZTUxZCJ9.aVbcvwQMaBkvec4sY_46BBSnoouGvehv7NT8kBgCgVivxBYZ155te9y68d_7e14t0sYcIa2d7jQfDk1lHupevWQlJtW8VwPDE456M5R79-aW-oh1Y-yBzv490l7SWGuSm5C3RvdFpzMKzpkblXuD4fzpXBxPHTEE8L7OfStnp34j_yw2gD6qU85ce72BdL7QFCan_V_5W62EXcL5UF4i0Qnd1jlTEWYOcBzShhfv8sCtOFOPqDMjXYWNdBnuGBM400fRlZFj-yKPUpl48Tpbln9m616RRTfV6wW8jqAnZFzLZTbe95PjiwiwFXP-yNzoqMAB3UpgjDtp92QsFXJ0YQ',
    '--client_id', 'ea03bc3e-aacf-4053-8fc9-996b0b169f58',
    '--patient_id', 'mof-85'
])
    
    revoke_token(args.url, args.token, args.client_id, args.patient_id)
