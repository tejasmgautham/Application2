import os
import json
import logging
from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_cors import CORS
import jwt
import requests
from urllib.parse import urlencode
from jose import jwk, jwt as jose_jwt
from jose.utils import base64url_decode
from dotenv import load_dotenv
from jwt.algorithms import RSAAlgorithm

# Load environment variables
load_dotenv()

# Flask app
app = Flask(__name__)
CORS(app)

# Configuration
KEYCLOAK_ISSUER = os.getenv("KEYCLOAK_ISSUER")
REALM = os.getenv("REALM")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
JWT_SECRET = os.getenv("JWT_SECRET")
JWKS_URL = os.getenv("JWKS_URL")
PORT = int(os.getenv("PORT", 5016))

# print("\n🔹 Keycloak Config:")
# print(f"  - ISSUER: {KEYCLOAK_ISSUER}")
# print(f"  - REALM: {REALM}")
# print(f"  - CLIENT_ID: {CLIENT_ID}")
# print(f"  - JWKS URL: {JWKS_URL}")

# Load JWKS (only once)
jwks_keys = requests.get(JWKS_URL).json()['keys']

def get_signing_key(kid):
    key = next((k for k in jwks_keys if k['kid'] == kid), None)
    if not key:
        raise Exception("Public key not found for given kid")
    return RSAAlgorithm.from_jwk(json.dumps(key))


@app.route('/alive')
def alive():
    return jsonify({"ack":"hello,  welcome"}) 

# Serve static files
@app.route('/app2.html')
def serve_app2():
    return render_template('app2.html') 

# Register user in Keycloak
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    first_name = data.get("first_name","user")
    last_name = data.get("last_name","test")
    phone = data.get("phone")

    jwt_token = request.headers.get("Authorization")
    if jwt_token:
        jwt_token = jwt_token.split(" ")[1]  # Extract token from "Bearer <token>"
    else:
        return jsonify({"success": False, "error": "Missing JWT token!"}), 400

    print(f"🔹 Registering User: {username}, Email: {email}, First Name: {first_name}, Last Name: {last_name}, Phone: {phone}")

    try:
        token_data = {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "client_credentials"
        }
        token_headers = {"Content-Type": "application/x-www-form-urlencoded"}
        token_response = requests.post(
            f"{KEYCLOAK_ISSUER}/realms/{REALM}/protocol/openid-connect/token",
            data=token_data,
            headers=token_headers
        )
        token_response.raise_for_status()
        admin_token = token_response.json()["access_token"]
        print("✅ Admin Token Received")

        create_user_payload = {
            "username": username,
            "firstName": first_name,
            "lastName": last_name,
            "email": email,
            "attributes": {"phone": phone},
            "enabled": True,
            "emailVerified": True,
            "credentials": [{"type": "password", "value": password, "temporary": False}]
        }
        user_response = requests.post(
            f"{KEYCLOAK_ISSUER}/admin/realms/{REALM}/users",
            headers={
                "Authorization": f"Bearer {admin_token}",
                "Content-Type": "application/json"
            },
            json=create_user_payload
        )
        user_response.raise_for_status()
        print("✅ User Created in Keycloak! Response Code:", user_response.status_code)

        location_header = user_response.headers.get("Location")
        if location_header:
            user_id = location_header.split("/")[-1]  # Extract user_id from URL
            print("🔹 New User ID:", user_id)

            update_response = requests.post(
                "http://localhost:5017/update_details",  # Your update_details URL
                json={"token": jwt_token, "user_id": user_id}
            )
            print("🔁 Update Details Response:", update_response.status_code, update_response.text)
            if update_response.status_code == 200:
                # ✅ Only now registration is truly successful
                return jsonify({"success": True, "message": "Registration successful!"}), 201
            else:
                try:
                    update_response_data = update_response.json()
                    message = update_response_data.get("error", "Update details failed")
                except Exception:
                    message = "Update details failed"

                return jsonify({"error": message}), update_response.status_code
        else:
            print("⚠️ No Location header found; cannot patch external-id")

        return jsonify({"success": True, "message": "Registration successful!"})

    except requests.exceptions.RequestException as e:
        print("❌ Registration Error:", e.response.json() if e.response else str(e))
        return jsonify({"success": False, "error": e.response.json() if e.response else str(e)}), 400
#Modify this except so that the actual error from update_details is displayed and not just ❌ Registration Failed: "409 Client Error: Conflict for url: http://localhost:8080/admin/realms/realm2/users"

# Verify token endpoint
@app.route("/verify-token", methods=["POST"])
def verify_token():
    print("🔹 Full Request Body:", request.json)
    print("🔹 Full Request Headers:", dict(request.headers))

    token = request.json.get("token") or request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        print("❌ Token is missing in request")
        return jsonify({"error": "Token is required"}), 400

    print("✅ Extracted Token:", token)
    try:
        unverified_header = jwt.get_unverified_header(token)
        print("🔹 Fetching JWKS Key for KID:", unverified_header["kid"])
        signing_key = get_signing_key(unverified_header["kid"])
        print(signing_key)
        decoded = jwt.decode(token, signing_key, algorithms=["RS256"], audience=["myclient","app2"])
        #audience=CLIENT_ID
        print("✅ Token Verified:", decoded)
        return jsonify({"valid": True, "userInfo": decoded})
    except Exception as e:
        print("❌ JWT Verification Failed:", str(e))
        return jsonify({"success": False, "error": "Invalid Keycloak token"}), 401

# Load app2 JSON details
with open("app2.json") as f:
    keycloak_data = json.load(f)

@app.route("/app2-details", methods=["GET"])
def app2_details():
    return jsonify(keycloak_data.get("app2", {}))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=True)
