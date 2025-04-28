from flask import Flask, request, jsonify
import json
import requests
import jwt
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  

# URLs to fetch Keycloak details from App1 (5015) & App2 (5016)
APP1_API_URL = "http://localhost:5000/app1-details"
APP2_API_URL = "http://localhost:5016/app2-details"

def get_keycloak_details(url):
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching details from {url}: {response.status_code}")
        return None

# Fetch App1 and App2 details dynamically
APP1_DETAILS = get_keycloak_details(APP1_API_URL)
APP2_DETAILS = get_keycloak_details(APP2_API_URL)

# Ensure details are fetched
if not APP1_DETAILS or not APP2_DETAILS:
    raise Exception("Failed to fetch Keycloak details")

KEYCLOAK_ISSUER = "http://localhost:8080"  # Keycloak base URL

REALM_APP1 = APP1_DETAILS["realm"]
CLIENT_ID_APP1 = APP1_DETAILS["client_id"]
CLIENT_SECRET_APP1 = APP1_DETAILS["client_secret"]

REALM_APP2 = APP2_DETAILS["realm"]
CLIENT_ID_APP2 = APP2_DETAILS["client_id"]
CLIENT_SECRET_APP2 = APP2_DETAILS["client_secret"]

def get_admin_token(realm, client_id, client_secret):
    try:
        url = f"{KEYCLOAK_ISSUER}/realms/{realm}/protocol/openid-connect/token"
        payload = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials"
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        
        response = requests.post(url, data=payload, headers=headers)
        response.raise_for_status()
        
        return response.json().get("access_token")
    
    except requests.RequestException as e:
        print(f"Error getting admin token: {e}")
        return None

def get_external_id_from_token(jwt_token, admin_token):
    try:
        decoded_token = jwt.decode(jwt_token, options={"verify_signature": False})
        print("Decoded Token:", decoded_token)
        user_id = decoded_token.get("sub")
        print("User ID from Token:", user_id)

        if not user_id:
            return None

        headers = {"Authorization": f"Bearer {admin_token}"}
        url = f"{KEYCLOAK_ISSUER}/admin/realms/{REALM_APP1}/users/{user_id}"
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            user_data = response.json()
            return user_data.get("attributes", {}).get("external-id", [None])[0]
        else:
            return None

    except Exception as e:
        print(f"Unexpected error: {e}")
        return None

def get_user_attributes_by_external_id(external_id, admin_token):
    try:
        headers = {"Authorization": f"Bearer {admin_token}"}
        url = f"{KEYCLOAK_ISSUER}/admin/realms/{REALM_APP2}/users?exact=true&q=external-id:{external_id}"
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            users = response.json()
            return users[0] if users else None
        return None

    except Exception as e:
        print(f"Unexpected error: {e}")
        return None

@app.route("/update_details", methods=["POST"])
def update_details():
    data = request.json
    jwt_token = data.get("token")
    user_id = data.get("user_id")  # Now we get the user_id from the register call

    if not jwt_token or not user_id:
        return jsonify({"error": "Missing token or user_id"}), 400

    # Get admin token for Realm1 and Realm2
    admin_token_app1 = get_admin_token(REALM_APP1, CLIENT_ID_APP1, CLIENT_SECRET_APP1)
    admin_token_app2 = get_admin_token(REALM_APP2, CLIENT_ID_APP2, CLIENT_SECRET_APP2)

    if not admin_token_app1 or not admin_token_app2:
        return jsonify({"error": "Failed to get admin tokens"}), 500

    # Decode the JWT to check audience
    decoded = jwt.decode(jwt_token, options={"verify_signature": False})
    audience = decoded.get("aud", [])
    if isinstance(audience, str):
        audience = [audience]

    # Only proceed if audience is "myclient"
    if "myclient" not in audience:
        return jsonify({"status": "Audience not myclient, no action needed"}), 200

    # Get external-id from Realm1 token
    external_id = get_external_id_from_token(jwt_token, admin_token_app1)
    if not external_id:
        return jsonify({"error": "External ID not found"}), 400

    headers_app2 = {"Authorization": f"Bearer {admin_token_app2}"}

    # First, check if any user in Realm2 already has this external-id
    existing_users = requests.get(
        f"{KEYCLOAK_ISSUER}/admin/realms/{REALM_APP2}/users",
        params={"q": f"external-id:{external_id}"},
        headers=headers_app2
    )

    if existing_users.status_code != 200:
        return jsonify({"error": "Failed to search users by external-id"}), 500

    existing_users_data = existing_users.json()

    if existing_users_data:
        # external-id already exists on some user, so we delete the newly created user
        delete_response = requests.delete(
            f"{KEYCLOAK_ISSUER}/admin/realms/{REALM_APP2}/users/{user_id}",
            headers=headers_app2
        )
        if delete_response.status_code == 204:
            return jsonify({"error": "User with external-id already exists. Already registered! "}), 409
        else:
            return jsonify({"error": "Failed to delete the newly created user"}), 500


    # Now, GET the full user details to keep all fields intact
    user_response = requests.get(
        f"{KEYCLOAK_ISSUER}/admin/realms/{REALM_APP2}/users/{user_id}",
        headers=headers_app2
    )

    if user_response.status_code != 200:
        return jsonify({"error": "Failed to fetch user details"}), 500

    user_data = user_response.json()

    # Ensure "attributes" exists
    if "attributes" not in user_data:
        user_data["attributes"] = {}

    # Add or update external-id in the attributes
    user_data["attributes"]["external-id"] = [external_id]

    # Now, PATCH only the updated fields (external-id), keeping the rest intact
    patch_response = requests.put(
        f"{KEYCLOAK_ISSUER}/admin/realms/{REALM_APP2}/users/{user_id}",
        headers={**headers_app2, "Content-Type": "application/json"},
        json=user_data  # Send the full user data with the updated external-id
    )

    if patch_response.status_code == 204:
        return jsonify({"status": "✅ External ID patched successfully"}), 200
    else:
        return jsonify({"error": "⚠️ Failed to patch external-id"}), 500


if __name__ == "__main__":
    app.run(port=5017, debug=True)
