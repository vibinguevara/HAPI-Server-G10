import requests

url = "https://digressingly-auriferous-lee.ngrok-free.dev/fhir/auth/token"

print("--- Test 1: Invalid Code ---")
data1 = {
    "grant_type": "authorization_code",
    "code": "INVALID_CODE_123",
    "client_id": "tdavis751076"
}
response1 = requests.post(url, data=data1)
print(f"Status Code: {response1.status_code}")
print(f"Response: {response1.text}")

print("\n--- Test 2: Missing auth code ---")
data2 = {
    "grant_type": "authorization_code",
    "client_id": "tdavis751076"
}
response2 = requests.post(url, data=data2)
print(f"Status Code: {response2.status_code}")
print(f"Response: {response2.text}")
