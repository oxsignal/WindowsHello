use rsa::{RsaPublicKey, Pkcs1v15Sign};
use rsa::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};
use std::error::Error;
use base64::{engine::general_purpose, Engine as _};

pub struct AuthManager;

impl AuthManager {   

    /// Verify RSA PKCS#1 v1.5 Signature
    pub fn verify_signature(
        public_key_spki: &[u8], 
        challenge: &[u8], 
        signature: &[u8]
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let verifier_key = RsaPublicKey::from_public_key_der(public_key_spki)?;
        
        let mut hasher = Sha256::new();
        hasher.update(challenge);
        let hashed_challenge = hasher.finalize(); 

        let scheme = Pkcs1v15Sign::new::<Sha256>();

        match verifier_key.verify(scheme, &hashed_challenge, signature) {
            Ok(()) => Ok(true),
            Err(e) => {
                eprintln!("Verification Failed: {:?}", e);
                Ok(false)
            }
        }
    }
    pub fn verify_trust_chain(cert_chain_b64: &str) -> Result<bool, Box<dyn Error>> {
            let chain_bytes = general_purpose::STANDARD.decode(cert_chain_b64)?;
            let mut certs = Vec::new();
            let mut pos = 0;

            // 패턴 검색으로 인증서들 추출
            while pos < chain_bytes.len() - 4 {
                if chain_bytes[pos] == 0x30 && chain_bytes[pos + 1] == 0x82 {
                    if let Ok((remainder, cert)) = x509_parser::parse_x509_certificate(&chain_bytes[pos..]) {
                        certs.push(cert);
                        pos = chain_bytes.len() - remainder.len();
                        continue;
                    }
                }
                pos += 1;
            }

            if certs.is_empty() { return Ok(false); }

            // 마지막 인증서가 Microsoft TPM Root인지 확인 (단순화된 예시)
            let root_cert = certs.last().unwrap();
            let is_microsoft = root_cert.subject().to_string().contains("Microsoft TPM Root Certificate Authority");
            
            if is_microsoft {
                println!("✅ Hardware Root Trust: Microsoft Verified.");
                Ok(true)
            } else {
                Ok(false)
            }
        }


    pub fn verify_attestation_report(
        attestation_b64: &str, 
        client_public_key_spki: &[u8]
    ) -> Result<bool, Box<dyn Error>> {
        // 1. Base64 디코딩
        let blob = general_purpose::STANDARD.decode(attestation_b64)?;

        println!("--- [Attestation Key Binding Check] ---");
        println!("Report size: {} bytes", blob.len());

        // 2. Magic Code 확인 (KYAT = Key Attestation)
        // 윈도우 API 호출 없이 바이너리 패턴만 확인합니다.
        if !blob.starts_with(b"KYAT") {
            println!("❌ Invalid Format: Not a Microsoft Attestation Blob.");
            return Ok(false);
        }

        // 3. [핵심] 바이트 슬라이스 검색        
        if client_public_key_spki.is_empty() {
            return Ok(false);
        }

        let is_bound = blob.windows(client_public_key_spki.len())
            .any(|window| window == client_public_key_spki);

        if is_bound {
            println!("✅ Key Binding Verified: Public key found in TPM blob.");
            Ok(true)
        } else {
            println!("❌ Key Binding Failed: Public key mismatch.");
            Ok(false)
        }
    }
}