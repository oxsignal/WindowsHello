use actix_web::{get, post, web, HttpResponse, Responder};
use rand::{distributions::Alphanumeric, Rng};
use base64::{engine::general_purpose, Engine as _};
use crate::types::{AppState, ChallengeRequest, ChallengeResponse, AuthRequest, UserData};
use crate::auth::AuthManager;

#[get("/challenge")]
pub async fn get_challenge(data: web::Data<AppState>, req: web::Query<ChallengeRequest>) -> impl Responder {
    let key_name = &req.key_name;
    let mut users = data.users.lock().unwrap();

    let challenge: Vec<u8> = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .collect();
    
    let challenge_b64 = general_purpose::STANDARD.encode(&challenge);

    users.entry(key_name.clone())
        .and_modify(|u| u.challenge = challenge.clone())
        .or_insert(UserData {
            public_key_spki: Vec::new(),
            challenge,
        });

    HttpResponse::Ok().json(ChallengeResponse {
        challenge_base64: challenge_b64,
        key_name: key_name.clone(),
    })
}

#[post("/authenticate")]
pub async fn authenticate(data: web::Data<AppState>, req: web::Json<AuthRequest>) -> impl Responder {
    let mut users = data.users.lock().unwrap();
    
    // 1. 사용자 데이터 조회
    let user_data = match users.get_mut(&req.key_name) {
        Some(d) => d,
        None => return HttpResponse::BadRequest().body("User not found"),
    };

    // 2. 공개키(SPKI) 확보
    let current_pk = if let Some(pk_b64) = &req.public_key_spki_base64 {
        match general_purpose::STANDARD.decode(pk_b64) {
            Ok(bytes) => {
                user_data.public_key_spki = bytes.clone(); // 신규 등록/교체
                bytes
            },
            Err(_) => return HttpResponse::BadRequest().body("Invalid public key format"),
        }
    } else {
        if user_data.public_key_spki.is_empty() {
            return HttpResponse::BadRequest().body("Public key not registered");
        }
        user_data.public_key_spki.clone()
    };

    // 3. [검증 1] 하드웨어 증명 확인 (Attestation Check)
    if let Some(report_b64) = &req.attest_blob_base64 {
        // 앞서 만든 verify_attestation_report 호출 (공개키 바인딩 확인 포함)
        match AuthManager::verify_attestation_report(report_b64, &current_pk) {
            Ok(true) => println!("🛡️ Hardware Attestation Verified for {}", req.key_name),
            _ => return HttpResponse::Unauthorized().body("가짜 TPM 혹은 위조된 공개키입니다."),
        }
    }

    // 4. 서명 검증 (Signature Verification)
    // 클라이언트가 보낸 챌린지 서명이 실제 공개키와 일치하는지 확인
    let sig_bytes = match general_purpose::STANDARD.decode(&req.signature_base64) {
        Ok(b) => b,
        Err(_) => return HttpResponse::BadRequest().body("Invalid signature format"),
    };

    match AuthManager::verify_signature(&current_pk, &user_data.challenge, &sig_bytes) {
        Ok(true) => {
            user_data.challenge.clear(); // Replay 공격 방지
            println!("✅ Login Successful: {}", req.key_name);
            HttpResponse::Ok().body(format!("✅ Welcome, {}", req.key_name))
        }
        _ => {
            println!("❌ Signature Verification Failed for {}", req.key_name);
            HttpResponse::Unauthorized().body("❌ Invalid Signature")
        }
    }
}