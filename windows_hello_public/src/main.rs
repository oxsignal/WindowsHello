use windows::{
    core::HSTRING,
    Security::Credentials::{KeyCredentialCreationOption, KeyCredentialManager},
    Security::Cryptography::CryptographicBuffer,            // ← 여기!
    Security::Cryptography::Core::CryptographicPublicKeyBlobType,
    Storage::Streams::{DataReader, IBuffer},
};

#[tokio::main]
async fn main() -> windows::core::Result<()> {
    // 0) 지원 여부
    if !KeyCredentialManager::IsSupportedAsync()?.await? {
        println!("Windows Hello/KeyCredential 미지원");
        return Ok(());
    }

    let key_name = HSTRING::from("example_user_key");

    // 1) 키 생성 (있으면 교체)
    let create = KeyCredentialManager::RequestCreateAsync(
        &key_name,
        KeyCredentialCreationOption::ReplaceExisting,
    )?
    .await?;

    // 2) KeyCredential 핸들
    let key = create.Credential()?; // ← Option 아님

    // 3) 공개키 가져오기: Blob 타입을 지정해야 함
    //    X509SubjectPublicKeyInfo = 표준 SPKI DER (서버 저장/검증에 가장 사용하기 좋음)
    let pk_buf: IBuffer = key.RetrievePublicKeyWithBlobType(
        CryptographicPublicKeyBlobType::X509SubjectPublicKeyInfo,
    )?;
    let public_key = ibuffer_to_vec(&pk_buf)?;
    println!("Public key (SPKI DER) len = {}", public_key.len());
    
    
    // 4) 서버가 준 챌린지를 서명(예시로 로컬 바이트)
    let challenge = b"server-random-challenge-123";
    let buf = CryptographicBuffer::CreateFromByteArray(challenge)?;
    let sig_result = key.RequestSignAsync(&buf)?.await?;
    let sig_buf = sig_result.Result()?;
    let signature = ibuffer_to_vec(&sig_buf)?;
    println!("Signature len = {}", signature.len());
    println!("Public key bytes = {:?}", public_key);
    println!("Signature bytes = {:?}", signature);
    
    Ok(())
}

// IBuffer -> Vec<u8>
fn ibuffer_to_vec(buf: &IBuffer) -> windows::core::Result<Vec<u8>> {
    let reader = DataReader::FromBuffer(buf)?;
    let len = reader.UnconsumedBufferLength()? as usize;
    let mut bytes = vec![0u8; len];
    reader.ReadBytes(&mut bytes)?;
    Ok(bytes)
}