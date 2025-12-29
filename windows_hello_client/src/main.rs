mod types;
mod hello;
mod network;

use windows::core::HSTRING;
use base64::{engine::general_purpose, Engine as _};
use crate::hello::HelloManager;
use crate::network::NetworkManager;
use crate::types::AuthRequest;

pub const BASE_URL: &str = "http://127.0.0.1:8080";
pub const KEY_NAME: &str = "abcd";

#[tokio::main]
async fn main() -> windows::core::Result<()> {
    // 0. System check: Ensure Windows Hello is supported on this device
    if !HelloManager::is_supported().await? {
        panic!("Windows Hello is not supported on this device.");
    }

    // Initialize managers with configuration
    let network = NetworkManager::new(BASE_URL);
    let key_name_h = HSTRING::from(KEY_NAME);
    let key_name_str = key_name_h.to_string_lossy();

    // 1. Key Preparation: Retrieve an existing key or create a new one, then obtain the Attestation Report
    let (key, public_key_b64) = HelloManager::get_key(&key_name_h).await?;
    let attestation_data = HelloManager::get_attestation(&key).await
        .expect("Failed to call get_attestation");

    // 2. Challenge Request: Obtain a unique nonce (challenge) from the server
    println!("[2] Requesting Challenge from the server...");
    let challenge_res = network.fetch_challenge(&key_name_str).await
        .expect("Failed to fetch challenge from server");

    let challenge_bytes = general_purpose::STANDARD.decode(&challenge_res.challenge_base64)
        .expect("Failed to decode challenge base64");

    // 3. Signing: Perform cryptographic signing via Windows Hello (triggers Biometric/PIN prompt)
    println!("[3] Signing the challenge with Windows Hello (TPM)...");
    let signature_b64 = HelloManager::sign_data(&key, &challenge_bytes).await?;

    let (cert_b64, blob_b64) = match attestation_data {
        Some((c, b)) => (Some(c), Some(b)),
        None => (None, None), // 기존 키 사용 시에는 증명서 생략 가능
    };

    // 4. Server Transmission: Send the signature and metadata to the server for verification
    let auth_data = AuthRequest {
        key_name: key_name_str,
        public_key_spki_base64: public_key_b64,
        signature_base64: signature_b64,
        cert_base64: cert_b64,
        attest_blob_base64: blob_b64,
    };

    println!("[4] Submitting authentication data...");
    match network.send_authentication(&auth_data).await {
        Ok(msg) => println!("✅ Authentication Success: {}", msg),
        Err(e) => println!("❌ Authentication Failed: {}", e),
    }

    Ok(())
}