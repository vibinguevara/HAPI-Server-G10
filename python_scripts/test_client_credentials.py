import jwt
import time
import requests
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 1. Generate an RSA private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Extract public key features for JWK
numbers = private_key.public_key().public_numbers()
def int_to_base64url(i):
    # Convert int to bytes, then base64url encode
    hex_str = hex(i)[2:]
    if len(hex_str) % 2 == 1:
        hex_str = '0' + hex_str
    b = bytes.fromhex(hex_str)
    import base64
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('utf-8')

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
        "alg": "RS256"
    }]
}

# The jku should ideally be a URL hosting the above JWKS. 
# For testing locally without setting up a lightweight HTTP server, we might fail if the java code strictly requires loading from a valid URL.
# Let's set up a quick localhost HTTP server in python to serve the JWKS!
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

class JWKRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(jwks).encode())
    def log_message(self, format, *args):
        pass

httpd = HTTPServer(('127.0.0.1', 8081), JWKRequestHandler)
thread = threading.Thread(target=httpd.serve_forever)
thread.daemon = True
thread.start()

print("[+] Started local JWKS server on http://127.0.0.1:8081/jwks.json")

# 2. Setup JWT claims
# 2. Setup JWT claims
client_id = "73582bd3-d1ab-4817-b124-a013b0e835df"
token_endpoint = "https://digressingly-auriferous-lee.ngrok-free.dev/fhir/auth/token"

headers = {
    "alg": "RS384",
    "typ": "JWT",
    "kid": kid,
    "jku": "http://127.0.0.1:8081/jwks.json" # The URL where the server can fetch our public key
}

payload = {
    "iss": client_id,
    "sub": client_id,
    "aud": token_endpoint,
    "exp": int(time.time()) + 300,
    "jti": str(uuid.uuid4())
}

# Serialize private key for pyjwt
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
    "scope": "system/*.rs"
}

print(f"[*] Sending token request to {token_endpoint}")
res = requests.post(token_endpoint, data=data, verify=False)

print(f"Token Status Code: {res.status_code}")
try:
    token_resp = res.json()
    print(json.dumps(token_resp, indent=2))
    access_token = token_resp.get("access_token")
    if access_token:
        patient_url = "https://digressingly-auriferous-lee.ngrok-free.dev/fhir/Patient?name=Bosco882"
        print(f"[*] Making GET request to {patient_url}")
        res_patient = requests.get(patient_url, headers={"Authorization": f"Bearer {access_token}"}, verify=False)
        print(f"Patient Status Code: {res_patient.status_code}")
        try:
            print(json.dumps(res_patient.json(), indent=2))
        except:
            print(res_patient.text)
except Exception as e:
    print(e)
    print(res.text)

httpd.shutdown()

