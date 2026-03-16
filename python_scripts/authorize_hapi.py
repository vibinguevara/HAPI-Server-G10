import jwt
import time
import requests
import uuid
import json
import urllib3
import logging
import threading
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from http.server import BaseHTTPRequestHandler, HTTPServer
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Client Configuration
CLIENT_ID = "73582bd3-d1ab-4817-b124-a013b0e835df"
TOKEN_ENDPOINT = "https://digressingly-auriferous-lee.ngrok-free.dev/fhir/auth/token"
SCOPES = "system/*.rs"
OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output.txt")

# 1. Generate an RSA private key
print("[*] Generating RSA Keypair...")
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

def int_to_base64url(i):
    hex_str = hex(i)[2:]
    if len(hex_str) % 2 == 1:
        hex_str = '0' + hex_str
    b = bytes.fromhex(hex_str)
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('utf-8')

numbers = private_key.public_key().public_numbers()
n = int_to_base64url(numbers.n)
e = int_to_base64url(numbers.e)
kid = str(uuid.uuid4())

jwks = {
    "keys": [{
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "n": n,
        "e": e,
        "alg": "RS384"
    }]
}

# Serve the JWKS locally
class JWKRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(jwks).encode())
    def log_message(self, format, *args):
        pass

jwks_port = 8089
httpd = HTTPServer(('127.0.0.1', jwks_port), JWKRequestHandler)
thread = threading.Thread(target=httpd.serve_forever)
thread.daemon = True
thread.start()
print(f"[+] Started local JWKS server on http://127.0.0.1:{jwks_port}/jwks.json")

# 2. Setup JWT claims
headers = {
    "alg": "RS384",
    "typ": "JWT",
    "kid": kid,
    "jku": f"http://127.0.0.1:{jwks_port}/jwks.json"
}

payload = {
    "iss": CLIENT_ID,
    "sub": CLIENT_ID,
    "aud": TOKEN_ENDPOINT,
    "exp": int(time.time()) + 300,
    "jti": str(uuid.uuid4())
}

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

client_assertion = jwt.encode(payload, pem, algorithm="RS384", headers=headers)

# 3. Call the Token endpoint
data = {
    "grant_type": "client_credentials",
    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion": client_assertion,
    "scope": SCOPES
}

print(f"[*] Sending token request to {TOKEN_ENDPOINT}...")
res = requests.post(TOKEN_ENDPOINT, data=data, verify=False)

# 4. Process response and write to output file
if res.status_code == 200:
    print("[+] Successfully received token response!")
    token_resp = res.json()
    
    with open(OUTPUT_FILE, "w") as f:
        f.write("=== HAPI FHIR Server Authorization ===\n\n")
        f.write(f"Timestamp: {time.ctime()}\n")
        f.write(f"Client ID: {CLIENT_ID}\n")
        f.write(f"Requested Scopes: {SCOPES}\n\n")
        
        f.write("--- TOKEN RESPONSE ---\n")
        f.write(f"Access Token:  {token_resp.get('access_token', 'N/A')}\n\n")
        f.write(f"Refresh Token: {token_resp.get('refresh_token', 'N/A')}\n\n")
        f.write(f"ID Token:      {token_resp.get('id_token', 'N/A')}\n\n")
        f.write(f"Granted Scope: {token_resp.get('scope', 'N/A')}\n")
        f.write(f"Expires In:    {token_resp.get('expires_in', 'N/A')} seconds\n")
        f.write(f"Token Type:    {token_resp.get('token_type', 'N/A')}\n\n")
        
        f.write("--- FULL JSON RESPONSE ---\n")
        f.write(json.dumps(token_resp, indent=2))
        
    print(f"[+] Output written successfully to {OUTPUT_FILE}")
else:
    print(f"[-] Token request failed with status code {res.status_code}")
    print(res.text)
    
    with open(OUTPUT_FILE, "w") as f:
        f.write("=== HAPI FHIR Server Authorization FAILED ===\n\n")
        f.write(f"Timestamp: {time.ctime()}\n")
        f.write(f"Status Code: {res.status_code}\n\n")
        f.write("Response Body:\n")
        f.write(res.text)
    
    print(f"[+] Error details written to {OUTPUT_FILE}")

# Shutdown JWKS server 
httpd.shutdown()
print("[*] JWKS server shut down.")
