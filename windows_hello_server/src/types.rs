use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::collections::HashMap;

pub struct AppState {
    pub users: Mutex<HashMap<String, UserData>>, 
}

pub struct UserData {
    pub public_key_spki: Vec<u8>,
    pub challenge: Vec<u8>,
}

#[derive(Deserialize)]
pub struct ChallengeRequest {
    pub key_name: String,
}

#[derive(Serialize)]
pub struct ChallengeResponse {
    pub challenge_base64: String,
    pub key_name: String,
}

#[derive(Deserialize)]
pub struct AuthRequest {
    pub key_name: String,
    pub public_key_spki_base64: Option<String>,
    pub signature_base64: String,
    pub cert_base64: Option<String>,
    pub attest_blob_base64: Option<String>,
}