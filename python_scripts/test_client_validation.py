import requests
import re
from urllib.parse import urlparse, parse_qs

# Step 1: Get an authorization code
print("--- Step 1: Getting Authorization Code ---")
auth_url = "https://digressingly-auriferous-lee.ngrok-free.dev/fhir/auth/authorize"
redirect_uri = "https://inferno.healthit.gov/suites/custom/smart/redirect"
client_id = "tdavis751076"
state = "12345"
code_challenge = "u1bZl8vFjJ7_KjG-1uDk242mE5dWYbS-QJw" # fake challenge
code_challenge_method = "S256"
scope = "launch/patient openid fhirUser offline_access patient/Observation.rs"

params = {
    "response_type": "code",
    "client_id": client_id,
    "redirect_uri": redirect_uri,
    "scope": scope,
    "state": state,
    "aud": "https://digressingly-auriferous-lee.ngrok-free.dev/fhir",
    "code_challenge": code_challenge,
    "code_challenge_method": code_challenge_method
}

# The endpoint returns HTML with a form. We need to submit the form to /auth/consent
response = requests.get(auth_url, params=params)
if response.status_code != 200:
    print(f"Failed to get auth page: {response.status_code}")
    exit(1)

# Step 2: Submit consent
print("--- Step 2: Submitting Consent ---")
consent_url = "https://digressingly-auriferous-lee.ngrok-free.dev/fhir/auth/consent"
consent_data = {
    "decision": "approve",
    "client_id": client_id,
    "redirect_uri": redirect_uri,
    "state": state,
    "code_challenge": code_challenge,
    "code_challenge_method": code_challenge_method,
    "aud": "https://digressingly-auriferous-lee.ngrok-free.dev/fhir",
    "approved_scopes": ["launch/patient", "openid", "fhirUser"]
}

# This returns a 302 redirect with the code in the URL query string
r = requests.post(consent_url, data=consent_data, allow_redirects=False)

if r.status_code not in [302, 303]:
    print(f"Failed to get code redirect. Status: {r.status_code}")
    exit(1)

location = r.headers['Location']
parsed_url = urlparse(location)
qs = parse_qs(parsed_url.query)
code = qs['code'][0]
print(f"Got code: {code}")

# Step 3: Exchange code using an INVALID client ID
print(f"\n--- Step 3: Testing with Invalid Client ID ---")
token_url = "https://digressingly-auriferous-lee.ngrok-free.dev/fhir/auth/token"

data = {
    "grant_type": "authorization_code",
    "code": code,
    "redirect_uri": redirect_uri,
    "client_id": "WRONG_CLIENT_ID"
}
response = requests.post(token_url, data=data)
print(f"Status Code: {response.status_code}")
print(f"Response: {response.text}")

if response.status_code == 401:
    print("\nSUCCESS: Server correctly rejected the valid code because the client_id did not match!")
else:
    print(f"\nFAIL: Server did not return 401. It returned {response.status_code}.")

