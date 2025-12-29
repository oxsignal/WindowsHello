use windows::core::HSTRING;
use windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType;
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Storage::Streams::{IBuffer, DataReader};
use base64::{engine::general_purpose, Engine as _};
use windows::Security::Credentials::{
    KeyCredentialManager, 
    KeyCredentialCreationOption, 
    KeyCredential, 
    KeyCredentialAttestationStatus,
    KeyCredentialStatus
};

pub struct HelloManager;

impl HelloManager {
    // Check Windows Hello is supported
    pub async fn is_supported() -> windows::core::Result<bool> {
        KeyCredentialManager::IsSupportedAsync()?.await
    }

    pub async fn get_key(name: &HSTRING) -> windows::core::Result<(KeyCredential, Option<String>)> {
        
        let open_op_result = KeyCredentialManager::OpenAsync(name);
        
        let open_result = match open_op_result {
            Ok(op) => op.await, 
            Err(e) => {        
                println!("   > System error during OpenAsync: {:?}", e);
                return Self::create_new_key(name).await;
            }
        };

        let key: KeyCredential;
        let mut public_key_b64: Option<String> = None;
        
        match open_result {
            Ok(retrieval_result) => {
            
                let mut status = retrieval_result.Status()?;                
                
                status = KeyCredentialStatus::NotFound; // For debugging. comment out when deploying

                if status == KeyCredentialStatus::Success {
                    println!("   > Key found locally. Proceeding to authentication.");
                    key = retrieval_result.Credential()?;
                } else {                    
                    println!("   > Key Not found");
                    let (new_key, pk) = Self::create_new_key(name).await?;
                    key = new_key;
                    public_key_b64 = pk;
                }
            }
            Err(e) => {
                println!("   > Key not found or access denied (Code: {:?}). Creating new...", e.code());
                let (new_key, pk) = Self::create_new_key(name).await?;
                key = new_key;
                public_key_b64 = pk;
            }
        }

        Ok((key, public_key_b64))
    }

    async fn create_new_key(name: &HSTRING) -> windows::core::Result<(KeyCredential, Option<String>)> {
        let creation_result = KeyCredentialManager::RequestCreateAsync(
            name,
            KeyCredentialCreationOption::ReplaceExisting,
        )?.await?;
        
        let key = creation_result.Credential()?;
        let pk_buf = key.RetrievePublicKeyWithBlobType(
            CryptographicPublicKeyBlobType::X509SubjectPublicKeyInfo,
        )?;
        
        let public_key = Self::ibuffer_to_vec(&pk_buf)?;
        let pk_b64 = Some(general_purpose::STANDARD.encode(&public_key));
        
        Ok((key, pk_b64))
    }

    // Get Attestation Report
    pub async fn get_attestation(key: &KeyCredential) -> windows::core::Result<Option<(String,String)>> {        
        let result = key.GetAttestationAsync()?.await?;        
        // buf to vec
        if result.Status()? == KeyCredentialAttestationStatus::Success {            
            let cert_chain_buf = result.CertificateChainBuffer()?;            
            let att_buf = result.AttestationBuffer()?;            

            let att_b64 = general_purpose::STANDARD.encode(&Self::ibuffer_to_vec(&att_buf)?);
            let cert_b64 = general_purpose::STANDARD.encode(&Self::ibuffer_to_vec(&cert_chain_buf)?);

            // 서버에 보낼 JSON 데이터에 두 필드를 모두 포함 (예: attestation_report, certificate_chain)
            Ok(Some((cert_b64, att_b64)))
        } else {
            println!("⚠️ Attestation failed with status: {:?}", result.Status()?);
            Ok(None)
        }
    }

    // Sign Challenge with Public key
    pub async fn sign_data(key: &KeyCredential, data: &[u8]) -> windows::core::Result<String> {
        let buf = CryptographicBuffer::CreateFromByteArray(data)?;
        let sig_result = key.RequestSignAsync(&buf)?.await?;
        let sig_buf = sig_result.Result()?;
        Ok(general_purpose::STANDARD.encode(&Self::ibuffer_to_vec(&sig_buf)?))
    }

    fn ibuffer_to_vec(buf: &IBuffer) -> windows::core::Result<Vec<u8>> {
        let reader = DataReader::FromBuffer(buf)?;
        let len = reader.UnconsumedBufferLength()? as usize;
        let mut bytes = vec![0u8; len];
        reader.ReadBytes(&mut bytes)?;
        Ok(bytes)
    }
}