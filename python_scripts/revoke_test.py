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
    '--token', 'eyJraWQiOiIxMGEyNzFhOC1jN2VjLTRhOGQtYjUzYi1iZGUxNTVkNTkzYmUiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJQYXRpZW50L21vZi04NSIsImlkX3Rva2VuX3N1YiI6Im1vZi04NSIsInBhdGllbnQiOiJtb2YtODUiLCJzY29wZSI6ImxhdW5jaC9wYXRpZW50IG9wZW5pZCBmaGlyVXNlciBvZmZsaW5lX2FjY2VzcyBwYXRpZW50L01lZGljYXRpb24ucnMgcGF0aWVudC9BbGxlcmd5SW50b2xlcmFuY2UucnMgcGF0aWVudC9DYXJlUGxhbi5ycyBwYXRpZW50L0NhcmVUZWFtLnJzIHBhdGllbnQvQ29uZGl0aW9uLnJzIHBhdGllbnQvRGV2aWNlLnJzIHBhdGllbnQvRGlhZ25vc3RpY1JlcG9ydC5ycyBwYXRpZW50L0RvY3VtZW50UmVmZXJlbmNlLnJzIHBhdGllbnQvRW5jb3VudGVyLnJzIHBhdGllbnQvR29hbC5ycyBwYXRpZW50L0ltbXVuaXphdGlvbi5ycyBwYXRpZW50L0xvY2F0aW9uLnJzIHBhdGllbnQvTWVkaWNhdGlvblJlcXVlc3QucnMgcGF0aWVudC9PYnNlcnZhdGlvbi5ycyBwYXRpZW50L09yZ2FuaXphdGlvbi5ycyBwYXRpZW50L1BhdGllbnQucnMgcGF0aWVudC9QcmFjdGl0aW9uZXIucnMgcGF0aWVudC9Qcm9jZWR1cmUucnMgcGF0aWVudC9Qcm92ZW5hbmNlLnJzIHBhdGllbnQvUHJhY3RpdGlvbmVyUm9sZS5ycyBwYXRpZW50L1NlcnZpY2VSZXF1ZXN0LnJzIHBhdGllbnQvQ292ZXJhZ2UucnMgcGF0aWVudC9NZWRpY2F0aW9uRGlzcGVuc2UucnMgcGF0aWVudC9TcGVjaW1lbi5ycyBwYXRpZW50L1JlbGF0ZWRQZXJzb24ucnMiLCJpc3MiOiJodHRwczovL2RpZ3Jlc3NpbmdseS1hdXJpZmVyb3VzLWxlZS5uZ3Jvay1mcmVlLmRldi9maGlyIiwiZW5jb3VudGVyIjoiOGM0MmRlMDktMTBkOS00ZGZmLTgwNDItNzA4YTM4OTlhZTEwIiwiZXhwIjoxNzcyODk0MjU3LCJpYXQiOjE3NzI4OTM5NTcsImZoaXJVc2VyIjoiaHR0cHM6Ly9kaWdyZXNzaW5nbHktYXVyaWZlcm91cy1sZWUubmdyb2stZnJlZS5kZXYvZmhpci9QcmFjdGl0aW9uZXIvYzM4ZTJkNmItYjJkNS0zZjhlLWFjYWUtMzA0NGVlYjVlZGJiIiwianRpIjoiNDI3ZjRmMmItNzZkZi00MDQ5LTkyNDktYTA5MTU5YzIzNjczIn0.MXE4J16BOzDJOpFgvrTLu5IwuNdLowB7MCxx9DVLrtkkrN0ZjL0GbZZTdYwgw2gfhGK6rSt2X4dDzeJE2XtRTlWu5OMTszVHp3S1jjRUpshZB2b0YWz7mc03MhuC-Ei92KMIHzZ9dggpv9YvHOG8pS16s5Fmc6OmC_PNMIpqk1eTacWHAK-UDOlfhHDJ90nDvOYYzZ7BuQ7p96Xdky_hS5s90YfBSjiewMlod72ACRYTxCqfUkSqmLkStreA1d7AqnjJb6G7b9eWmJeNyHIrnZz997AmD3uUl7LXVq6ArdefdBkHFTfW3lxvenqQJ2paBmxJ6maO_4g8Lwaskrv0cw',
    '--client_id', 'tdavis751076',
    '--patient_id', 'mof-85'
])
    
    revoke_token(args.url, args.token, args.client_id, args.patient_id)
