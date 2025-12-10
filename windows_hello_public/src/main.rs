use windows::core::HSTRING;
// Import necessary types for KeyCredential management
use windows::Security::Credentials::{KeyCredentialManager, KeyCredentialCreationOption}; 
use windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType; 
use windows::Security::Cryptography::CryptographicBuffer; 
use windows::Storage::Streams::{IBuffer, DataReader};
use serde::{Serialize, Deserialize};
use reqwest::Client;
use base64::{engine::general_purpose, Engine as _};

// =========================================================
// 🌐 Data Transfer Structures (Client/Server Communication)
// =========================================================

// 1. Server response for the initial challenge request
#[derive(Deserialize, Debug)]
struct ChallengeResponse {
    challenge_base64: String, // Base64 encoded nonce challenge    
}

// 2. Client request for authentication (sending signature and key)
#[derive(Serialize, Debug)]
struct AuthRequest {
    key_name: String,
    public_key_spki_base64: Option<String>, // Public Key (SPKI DER) for registration phase
    signature_base64: String,
}

// Helper function: IBuffer (WinRT) -> Vec<u8> (Rust standard)
fn ibuffer_to_vec(buf: &IBuffer) -> windows::core::Result<Vec<u8>> {
    let reader = DataReader::FromBuffer(buf)?;
    let len = reader.UnconsumedBufferLength()? as usize;
    let mut bytes = vec![0u8; len];
    reader.ReadBytes(&mut bytes)?;
    Ok(bytes)
}

// =========================================================
// 🚀 Client Main Logic (Windows Hello Authentication Flow)
// =========================================================

#[tokio::main]
async fn main() -> windows::core::Result<()> {
    
    // 0) Windows Hello 지원 여부 확인
    if !KeyCredentialManager::IsSupportedAsync()?.await? {
        println!("Windows Hello/KeyCredential 미지원");
        return Ok(());
    }

    let client = Client::new();
    let base_url = "http://127.0.0.1:8080"; 
    let key_name = HSTRING::from("example_user_key");
    let rust_key_name = key_name.to_string_lossy();
        let key: windows::Security::Credentials::KeyCredential; // key 타입을 명시적으로 지정
    let mut public_key_b64: Option<String> = None; 

    // --- 1. 키 존재 여부 확인 및 생성 ---
    println!("[1] Checking for existing key: {}", rust_key_name);
    
    // KeyCredentialManager::OpenAsync를 사용하여 키를 열어봅니다.
    let open_result = KeyCredentialManager::OpenAsync(&key_name)?.await;
    
    // open_result는 KeyCredentialRetrievalResult 객체를 반환합니다.
    if let Ok(retrieval_result) = open_result {
        // --- 1-1. 키가 이미 존재함 (인증 플로우) ---
        println!("   > Key found locally. Proceeding to authentication.");
        
        // KeyCredentialRetrievalResult에서 KeyCredential 객체를 추출
        key = retrieval_result.Credential()?; 

    } else {
        // --- 1-2. 키가 존재하지 않음 (등록 플로우) ---
        println!("   > Key not found. Requesting new key creation...");
        
        let retrieval_result = KeyCredentialManager::RequestCreateAsync(
            &key_name,
            KeyCredentialCreationOption::ReplaceExisting,
        )?.await?;
        
        // KeyCredentialRetrievalResult에서 KeyCredential 객체를 추출
        key = retrieval_result.Credential()?; 
        
        // 새로 생성된 키의 공개키를 서버에 등록하기 위해 추출
        let pk_buf: IBuffer = key.RetrievePublicKeyWithBlobType(
            CryptographicPublicKeyBlobType::X509SubjectPublicKeyInfo,
        )?;       
        
        let public_key = ibuffer_to_vec(&pk_buf)?;
        public_key_b64 = Some(general_purpose::STANDARD.encode(&public_key));
    }

    // --- 2. Request Challenge from the server ---
    println!("[2] Request Challenge from the server...");         
    
    // Request challenge using the key name as a query parameter
    let challenge_url = format!("{}/challenge?key_name={}", base_url, rust_key_name);
    let challenge_response = client.get(&challenge_url)
        .send().await
        .expect("Failed to request challenge");

    // Check HTTP status code
    if !challenge_response.status().is_success() {
        println!("❌ Server Response Failed: Status Code {}", challenge_response.status());
        let error_body = challenge_response.text().await.unwrap_or_else(|_| "No body received".to_string());
        println!("❌ Server Response Body: {}", error_body);
        panic!("Server returned an error status code.");
    }
    
    // Read and parse the response body
    let response_text = challenge_response.text().await.expect("Failed to read response text");
    println!("Debug: {}", response_text); // Debug the received JSON string

    // Parse JSON to get the challenge
    let challenge_res: ChallengeResponse = serde_json::from_str(&response_text)
        .expect("Failed to parse challenge response JSON");
        
    // Decode the Base64 challenge bytes
    let challenge_bytes = general_purpose::STANDARD.decode(&challenge_res.challenge_base64)
    .expect("Failed to decode Challenge Base64");
    
    println!("    > Challenge received. Length: {} bytes", challenge_bytes.len());

    
    // --- 3. Sign the Challenge with TPM (Windows Hello) ---
    println!("[3] Requesting signature with Windows Hello (TPM)...");
    
    // Convert the challenge bytes to IBuffer (required by Windows API)
    let buf = CryptographicBuffer::CreateFromByteArray(&challenge_bytes)?;
    
    // Request signing operation (triggers the Windows Hello PIN/Biometric prompt)
    let sig_result = key.RequestSignAsync(&buf)?.await?;
    let sig_buf = sig_result.Result()?;
    
    // Convert the signature IBuffer result to Vec<u8> and Base64 encode
    let signature = ibuffer_to_vec(&sig_buf)?;
    let signature_b64 = general_purpose::STANDARD.encode(&signature);
    
    println!("    > Signing complete. Signature Length: {} bytes", signature.len());


     // --- 4. 서명 결과를 서버에 전송 ---
    println!("[4] Sending signature result to the server...");
    
    // AuthRequest 생성 시, 1단계에서 얻은 public_key_b64 값을 사용합니다.
    let auth_data = AuthRequest {
        key_name: rust_key_name.into(),
        // 키가 새로 생성된 경우에만 Some(공개키), 아니면 None을 전송합니다.
        public_key_spki_base64: public_key_b64,
        signature_base64: signature_b64,
    };

    let auth_res = client.post(&format!("{}/authenticate", base_url))
        .json(&auth_data)
        .send().await
        .expect("Authentication request failed");
        
    // Check server response
    if auth_res.status().is_success() {         
        // Read response body upon success
        println!("✅ Server Authentication Success! Response: {:?}", auth_res.text().await.expect("Failed to read success response body"));
    } else {
        // Read response body upon failure
        println!("❌ Server Authentication Failed! Status Code: {}", auth_res.status());         
        println!("    > Response Body: {:?}", auth_res.text().await.expect("Failed to read error response body"));
    }

    Ok(())
}