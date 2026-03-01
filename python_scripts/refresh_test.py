import requests
import argparse
import sys

# Default Endpoint URL
DEFAULT_URL = 'https://digressingly-auriferous-lee.ngrok-free.dev/fhir/auth/revoke'

def refresh_token(url, refresh_token_val):
    print("Attempting to refresh token...")
    
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token_val
    }
        
    print(f"Sending parameters: {data}")
    print(f"To endpoint: {url}")
    
    try:
        response = requests.post(url, data=data)
        
        # Check if the request was successful
        if response.status_code == 200:
            print(f"ERROR: Server returned 200 OK for an INVALID/REVOKED refresh token.")
            print(f"Response: {response.text}")
            sys.exit(1)
        elif response.status_code == 401:
            print(f"SUCCESS: Server correctly returned 401 Unauthorized.")
            print(f"Response: {response.text}")
            sys.exit(0)
        else:
            print(f"UNEXPECTED: Server returned status code: {response.status_code}")
            print(f"Response: {response.text}")
            sys.exit(1)
            
    except requests.exceptions.RequestException as e:
        print(f"Error calling the endpoint: {e}")
        sys.exit(1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Test refresh token endpoint with revoked token")
    parser.add_argument('--url', type=str, default=DEFAULT_URL, help="Token endpoint URL")
    parser.add_argument('--token', type=str, default="some-invalid-or-revoked-token-12345", help="Refresh token to test")
    
    args = parser.parse_args([
    '--url', 'https://digressingly-auriferous-lee.ngrok-free.dev/fhir/auth/revoke',
    '--token', '5d74d2cb-588d-4653-857e-55f3a8f1628b'
])
    refresh_token(args.url, args.token)
