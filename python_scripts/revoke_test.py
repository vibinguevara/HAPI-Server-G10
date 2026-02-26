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
    '--token', 'eyJraWQiOiJjOGQyYTAzOS02YmNkLTRiMTMtYmVhNS00ZDU4OTQ3OTI3MGUiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2RpZ3Jlc3NpbmdseS1hdXJpZmVyb3VzLWxlZS5uZ3Jvay1mcmVlLmRldi9maGlyIiwic3ViIjoiUGF0aWVudC9tb2YtODUiLCJleHAiOjE3NzIxMjkwOTgsImlhdCI6MTc3MjEyODc5OCwianRpIjoiODc2N2YzMjUtNWE1NC00MDE4LWI4ZDQtY2Y5YTk2ZjU5MWNhIiwic2NvcGUiOiJsYXVuY2ggb3BlbmlkIGZoaXJVc2VyIG9mZmxpbmVfYWNjZXNzIHVzZXIvTWVkaWNhdGlvbi5ycyB1c2VyL0FsbGVyZ3lJbnRvbGVyYW5jZS5ycyB1c2VyL0NhcmVQbGFuLnJzIHVzZXIvQ2FyZVRlYW0ucnMgdXNlci9Db25kaXRpb24ucnMgdXNlci9EZXZpY2UucnMgdXNlci9EaWFnbm9zdGljUmVwb3J0LnJzIHVzZXIvRG9jdW1lbnRSZWZlcmVuY2UucnMgdXNlci9FbmNvdW50ZXIucnMgdXNlci9Hb2FsLnJzIHVzZXIvSW1tdW5pemF0aW9uLnJzIHVzZXIvTG9jYXRpb24ucnMgdXNlci9NZWRpY2F0aW9uUmVxdWVzdC5ycyB1c2VyL09ic2VydmF0aW9uLnJzIHVzZXIvT3JnYW5pemF0aW9uLnJzIHVzZXIvUGF0aWVudC5ycyB1c2VyL1ByYWN0aXRpb25lci5ycyB1c2VyL1Byb2NlZHVyZS5ycyB1c2VyL1Byb3ZlbmFuY2UucnMgdXNlci9QcmFjdGl0aW9uZXJSb2xlLnJzIHVzZXIvU2VydmljZVJlcXVlc3QucnMgdXNlci9Db3ZlcmFnZS5ycyB1c2VyL01lZGljYXRpb25EaXNwZW5zZS5ycyB1c2VyL1NwZWNpbWVuLnJzIHVzZXIvUmVsYXRlZFBlcnNvbi5ycyJ9.mO6hG0W08uBl5NBSqnpntiFxH8gsteWtIUiDaPBHCA5uvqTut2glkrOF5UBfu5pzuIdOToi9GeTbGMwNlKlo6EX_J0zAuilGA2mH52k8F5Bg5BJniKe2tWQn5tJoa3qK7RbU9sTiWMxSHQEtELh8cWjhxCfNth14I1W5ryANXUeVEDbRsVEzFcecrQTijk05JhmOgwQhQq2DUn0qYSfXPIY5kD-lUlbwlOKA7X0H7w8sqQQU6d6ejOL1FF_WnVh4fxOH38lvMeAwCmCrKaa_KmGkf93OARlcdbcjzMDEr-VOOvhOiwr2c1t4d-MLPBlLa9xPViUxXxWj9fcTrn8MBQ',
    '--client_id', 'tdavis751076',
    '--patient_id', 'mof-85'
])
    
    revoke_token(args.url, args.token, args.client_id, args.patient_id)
