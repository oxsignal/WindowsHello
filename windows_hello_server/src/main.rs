use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize};
use std::sync::Mutex;
use std::collections::HashMap;

// Signing and verification imports
use rsa::{RsaPublicKey, Pkcs1v15Sign};
use rsa::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};
use rand::{distributions::Alphanumeric, Rng};
use base64::{engine::general_purpose, Engine as _};

// =========================================================
// 🌐 Data Structures (Server State & Communication)
// =========================================================

// Structure for GET /challenge query parameters
#[derive(Deserialize)]
struct ChallengeRequest {
    key_name: String, // Key ID used to identify the user's credential
}

// Structure for POST /authenticate body
#[derive(Deserialize)]
struct AuthRequest {
    key_name: String,
    public_key_spki_base64: Option<String>, // Public key (optional, sent during initial registration)
    signature_base64: String, // Signature result from the TPM/Windows Hello
}

// Application State for in-memory storage (simulating a database)
struct AppState {
    // Maps key_name to UserData
    users: Mutex<HashMap<String, UserData>>, 
}

// User data stored on the server
struct UserData {
    public_key_spki: Vec<u8>, // X509 SPKI DER Public Key bytes (for verification)
    challenge: Vec<u8>,       // The active nonce challenge issued to the client
}

// =========================================================
// 1. Challenge Endpoint: GET /challenge
// =========================================================

/// Generates a unique nonce challenge and stores it for the given key_name.
#[get("/challenge")]
async fn get_challenge(data: web::Data<AppState>, req: web::Query<ChallengeRequest>) -> impl Responder {
    let key_name = &req.key_name;
    let mut users = data.users.lock().unwrap();

    // 1) Generate a 32-byte random challenge (nonce)
    let challenge: Vec<u8> = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .collect();
    
    let challenge_b64 = general_purpose::STANDARD.encode(&challenge);

    // 2) Store or update the active challenge for the key_name
    if let Some(user_data) = users.get_mut(key_name) {
        // Existing user: Update the challenge
        user_data.challenge = challenge;
    } else {
        // New user: Store the challenge and initialize public key as empty
        users.insert(key_name.clone(), UserData {
            public_key_spki: Vec::new(), 
            challenge,
        });
    }

    // Return the Base64 encoded challenge
    HttpResponse::Ok().json(serde_json::json!({
        "challenge_base64": challenge_b64,
        "key_name": key_name // Key name is included for clarity in this response
    }))
}

// =========================================================
// 2. Authentication Endpoint: POST /authenticate
// =========================================================

/// Receives the signed challenge and verifies the signature using the stored public key.
#[post("/authenticate")]
async fn authenticate(data: web::Data<AppState>, req: web::Json<AuthRequest>) -> impl Responder {
    let mut users = data.users.lock().unwrap();
    let key_name = &req.key_name;
    
    // Find user data by key_name
    let user_data = match users.get_mut(key_name) {
        Some(d) => d,
        None => return HttpResponse::BadRequest().body("Error: Unknown key name (User not found)"),
    };

    // --- A. Public Key Registration/Update (If provided by the client) ---
    if let Some(pk_b64) = &req.public_key_spki_base64 {
        if user_data.public_key_spki.is_empty() {
             println!("🔑 New Public Key received for {}", key_name);
        }
        // Decode and store the new public key
        user_data.public_key_spki = general_purpose::STANDARD.decode(pk_b64).unwrap();
    }
    
    let public_key_spki = &user_data.public_key_spki;
    if public_key_spki.is_empty() {
        return HttpResponse::BadRequest().body("Error: Public Key not registered for this user.");
    }
    
    // Retrieve the original challenge and signature from the request
    let original_challenge = &user_data.challenge;
    let signature_bytes = match general_purpose::STANDARD.decode(&req.signature_base64) {
        Ok(sig) => sig,
        Err(_) => return HttpResponse::BadRequest().body("Error: Invalid signature base64 format."),
    };

    // --- B. Signature Verification Logic ---
    match verify_signature(public_key_spki, original_challenge, &signature_bytes) {
        Ok(true) => {
            // Authentication Success: Clear the challenge to prevent replay attacks
            user_data.challenge = Vec::new(); 
            HttpResponse::Ok().body(format!("✅ Authentication Successful for {}", key_name))
        },
        _ => {
            HttpResponse::Unauthorized().body("❌ Authentication Failed: Invalid signature or key.")
        }
    }
}


// =========================================================
// 3. Signature Verification Function (Core Logic)
// =========================================================

/// Verifies the signature using the RSA Public Key, the original challenge, and the signature bytes.
fn verify_signature(public_key_spki: &[u8], challenge: &[u8], signature: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
    
    // 1. Parse the Public Key (SPKI DER format) into an RsaPublicKey object
    let verifier_key = RsaPublicKey::from_public_key_der(public_key_spki)?;

    // 2. Hash the original Challenge data using SHA-256 (as the signature covers the digest)
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    let hashed_challenge = hasher.finalize(); 

    // 3. Set up the verification scheme: PKCS#1 v1.5 + SHA256 (Windows Hello default)
    let scheme = Pkcs1v15Sign::new::<Sha256>();

    // 4. Perform the signature verification
    // 'verifier_key.verify' returns Result<(), Error>
    match verifier_key.verify(scheme, hashed_challenge.as_slice(), signature) {
        Ok(()) => Ok(true), // Verification successful
        Err(e) => {
            println!("Verification Error: {:?}", e);
            Ok(false) // Verification failed
        },
    }
}

// =========================================================
// 🚀 Server Initialization
// =========================================================

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize the in-memory storage (database simulation)
    let app_data = web::Data::new(AppState {
        users: Mutex::new(HashMap::new()),
    });

    println!("🚀 Server running at http://127.0.0.1:8080");

    HttpServer::new(move || {
        App::new()
            .app_data(app_data.clone())
            .service(get_challenge)
            .service(authenticate)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}