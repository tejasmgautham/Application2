require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const path = require("path");
const axios = require("axios");
const fs = require("fs");
const jwksClient = require("jwks-rsa"); 

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"))); // Serve app2.html

// ✅ Load Config from .env
const KEYCLOAK_ISSUER = process.env.KEYCLOAK_ISSUER;
const REALM = process.env.REALM;
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const JWT_SECRET = process.env.JWT_SECRET;
const JWKS_URL = process.env.JWKS_URL; // ✅ JWKS URL for Public Keys

console.log("🔹 Keycloak Config:");
console.log(`  - ISSUER: ${KEYCLOAK_ISSUER}`);
console.log(`  - REALM: ${REALM}`);
console.log(`  - CLIENT_ID: ${CLIENT_ID}`);
console.log(`  - JWKS URL: ${JWKS_URL}`);

// ✅ Setup JWKS Client for JWT Verification
const client = jwksClient({ jwksUri: JWKS_URL });

// ✅ Fetch Public Key for JWT Verification
async function getKey(header, callback) {
    console.log("🔹 Fetching JWKS Key for KID:", header.kid);
    client.getSigningKey(header.kid, (err, key) => {
        if (err) {
            console.error("❌ JWKS Key Fetch Error:", err);
            return callback(err);
        }
        const signingKey = key.publicKey || key.rsaPublicKey;
        console.log("✅ JWKS Key Retrieved Successfully");
        callback(null, signingKey);
    });
}

// ✅ Register User in Keycloak
app.post("/register", async (req, res) => {
    const { username, email, password, externalId } = req.body;
    console.log(`🔹 Registering User: ${username}, Email: ${email}, ExternalID: ${externalId}`);

    try {
        // 🔹 Step 1: Get Admin Token from Keycloak
        const tokenResponse = await axios.post(
            `${KEYCLOAK_ISSUER}/realms/${REALM}/protocol/openid-connect/token`,
            new URLSearchParams({
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                grant_type: "client_credentials",
            }),
            { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
        );

        const adminToken = tokenResponse.data.access_token;
        console.log("✅ Admin Token Received");

        // 🔹 Step 2: Create User in Keycloak
        const createUserResponse = await axios.post(
            `${KEYCLOAK_ISSUER}/admin/realms/${REALM}/users`,
            {
                username,
                email,
                firstName: "User",
                lastName: "Test",
                enabled: true,
                emailVerified: true,
                attributes: { "external-id": externalId },
                credentials: [{ type: "password", value: password, temporary: false }],
            },
            { headers: { Authorization: `Bearer ${adminToken}`, "Content-Type": "application/json" } }
        );

        console.log("✅ User Created in Keycloak! Response Code:", createUserResponse.status);
        res.json({ success: true, message: "Registration successful!" });

    } catch (err) {
        console.error("❌ Registration Error:", err.response?.data || err.message);
        res.status(400).json({ success: false, error: err.response?.data || err.message });
    }
});

// Secure Token Verification Endpoint for App2 (verify custom JWTs)
app.post("/verify-token", (req, res) => {
    console.log("🔹 Full Request Body:", req.body);
    console.log("🔹 Full Request Headers:", req.headers);

    const token = req.body.token || req.headers.authorization?.split(" ")[1];

    if (!token) {
        console.error("❌ Token is missing in request");
        return res.status(400).json({ error: "Token is required" });
    }

    console.log("✅ Extracted Token:", token);

    jwt.verify(token, getKey, { algorithms: ["RS256"] }, (err, decoded) => {
        if (err) {
            console.error("❌ JWT Verification Failed:", err.message);
            return res.status(401).json({ success: false, error: "Invalid Keycloak token" });
        }
        console.log("✅ Token Verified:", decoded);
        res.json({ valid: true, userInfo: decoded });
    });
});

// Load keycloak details from JSON
const keycloakData = JSON.parse(fs.readFileSync("app2.json", "utf8"));

// API to send app2 details
app.get("/app2-details", (req, res) => {
    res.json(keycloakData.app2);
});

const PORT = process.env.PORT || 5016;
app.listen(PORT, () => console.log(`🚀 App2 server running on http://localhost:${PORT}`));
