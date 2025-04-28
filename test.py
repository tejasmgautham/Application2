import json
import requests
import jwt

# Load App2 details from JSON
with open("app2_details.json", "r") as file:
    APP2_DETAILS = json.load(file)["app2"]

KEYCLOAK_ISSUER = "http://localhost:8080"  # Keycloak base URL
REALM_APP2 = APP2_DETAILS["realm"]
CLIENT_ID_APP2 = APP2_DETAILS["client_id"]
CLIENT_SECRET_APP2 = APP2_DETAILS["client_secret"]

def get_admin_token(realm, client_id, client_secret):
    """
    Fetches an admin token from Keycloak for API access.
    """
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
    """
    Extracts the user_id from the JWT and fetches the external-id from Keycloak (App1).
    """
    try:
        decoded_token = jwt.decode(jwt_token, options={"verify_signature": False})
        user_id = decoded_token.get("sub")  # ✅ Extract 'sub' from Keycloak token

        if not user_id:
            raise ValueError("User ID (sub) not found in token")

        # Fetch user details from Keycloak (App1)
        headers = {"Authorization": f"Bearer {admin_token}"}
        url = f"{KEYCLOAK_ISSUER}/admin/realms/{REALM_APP2}/users/{user_id}"
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            user_data = response.json()
            external_id = user_data.get("attributes", {}).get("external-id", [None])[0]
            return external_id
        else:
            print(f"Error fetching user from App1: {response.status_code} - {response.text}")
            return None

    except jwt.ExpiredSignatureError:
        print("JWT token has expired")
    except jwt.DecodeError:
        print("Error decoding JWT token")
    except Exception as e:
        print(f"Unexpected error: {e}")
    return None

def get_user_attributes_by_external_id(external_id, admin_token):
    """
    Fetches user attributes from Keycloak (App2) using external-id.
    """
    try:
        if not external_id:
            raise ValueError("External ID is required")

        headers = {"Authorization": f"Bearer {admin_token}"}
        url = f"{KEYCLOAK_ISSUER}/admin/realms/{REALM_APP2}/users?exact=true&q=external-id:{external_id}"
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            users = response.json()
            if users:
                return users[0]  # Return the first matching user
            else:
                print("No matching user found in App2")
                return None
        else:
            print(f"Error fetching user attributes from App2: {response.status_code} - {response.text}")
            return None

    except Exception as e:
        print(f"Unexpected error: {e}")
        return None

# ✅ Processing the JWT Token from App2
def process_token_from_app2(jwt_token):
    """
    Main function that takes the JWT token from App2, 
    fetches external-id from App1, and finds the matching user in App2.
    """
    # 🔹 Get admin tokens dynamically
    admin_token_app2 = get_admin_token(REALM_APP2, CLIENT_ID_APP2, CLIENT_SECRET_APP2)

    if not admin_token_app2:
        return "❌ Failed to get admin token"

    # 🔹 Extract external-id from App1
    external_id = get_external_id_from_token(jwt_token, admin_token_app2)
    
    if external_id:
        # 🔹 Fetch user in App2 using external-id
        user_data = get_user_attributes_by_external_id(external_id, admin_token_app2)
        
        if user_data:
            return {"status": "✅ User Found", "user_data": user_data}
        else:
            return "❌ No matching user found in App2"
    else:
        return "❌ External ID not found"
