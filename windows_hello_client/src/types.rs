use serde::{Serialize, Deserialize};

#[derive(Deserialize, Debug)]
pub struct ChallengeResponse {
    pub challenge_base64: String,
}

#[derive(Serialize, Debug)]
pub struct AuthRequest {
    pub key_name: String,
    pub public_key_spki_base64: Option<String>,
    pub signature_base64: String,
    pub cert_base64: Option<String>,
    pub attest_blob_base64: Option<String>,
}