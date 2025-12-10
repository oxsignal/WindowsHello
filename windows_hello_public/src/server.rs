// =========================================================
    // 4) 서명 검증 (Server Side Simulation)
    // =========================================================
    
    // (A) DER 바이트에서 RSA 공개키 객체 복원
    let pub_key_obj = RsaPublicKey::from_public_key_der(&public_key)
            .map_err(|e| windows::core::Error::new(
                windows::core::HRESULT(0), 
                // format!()의 결과인 String을 그대로 전달합니다.
                format!("Key Parse Error: {}", e) 
            ))?;
    // (B) 원본 Challenge 데이터를 SHA-256으로 해시 (추가된 로직)
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    // finalize()는 해시 결과를 반환합니다.
    let hashed_challenge = hasher.finalize(); 

    // (C) 검증 스키마 설정: Windows Hello 기본값은 보통 PKCS#1 v1.5 + SHA256
    let scheme = Pkcs1v15Sign::new::<Sha256>();

    // (D) 해시된 값(Digest)을 사용하여 검증 수행
    // Note: hashed_challenge.as_slice() 대신 &hashed_challenge를 바로 사용할 수도 있습니다.
    match pub_key_obj.verify(scheme, hashed_challenge.as_slice(), &signature) {
        Ok(_) => println!(">> [Success] 서명이 유효합니다."),
        Err(e) => println!(">> [Error] 서명이 유효하지 않습니다: {:?}", e),
    }