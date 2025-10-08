// --- 외부 라이브러리 관련 ---
use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use once_cell::sync::Lazy;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

// 암호화 및 서명 검증 관련
use rsa::signature::Verifier;
use sha2::{Digest, Sha256};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey};
use spki::DecodePublicKey;  // p256, rsa 처럼 public key DER decoding용
use pkcs8::spki::SubjectPublicKeyInfo;
use der::{Any, Decode};  // der decoding 및 trait
use hex;

// PEM 인코딩 관련
use pem_rfc7468 as pem;

// --- 표준 라이브러리 ---
use std::{
    collections::HashMap,
    fs,
    net::SocketAddr,
    sync::Mutex,
};

static USERS: Lazy<Mutex<HashMap<String, UserKey>>> = Lazy::new(|| Mutex::new(HashMap::new()));



#[derive(Clone)]
struct UserKey {
    spki_der: Vec<u8>,
    fpr: [u8; 32],
}

fn spki_fpr_sha256(spki_der: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(spki_der);
    h.finalize().into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddResult {
    Inserted,  // 신규 추가
    Replaced,  // 기존 키 교체
}

fn add_user_key(user_id: &str, spki_der: Vec<u8>) -> (AddResult, [u8; 32]) {
    let fpr = spki_fpr_sha256(&spki_der);
    let mut m = USERS.lock().unwrap();
    let prev = m.insert(user_id.to_string(), UserKey { spki_der, fpr });
    let outcome = if prev.is_none() { AddResult::Inserted } else { AddResult::Replaced };
    (outcome, fpr)
}


fn spki_der_from_pubkey_pem(pem_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let (label, der_bytes) = pem::decode_vec(pem_bytes).map_err(|e| format!("pem decode: {e}"))?;
    if label != "PUBLIC KEY" {
        return Err(format!("unsupported PEM label: {label}"));
    }
    // 검증: SPKI 형태인지 확인
    let _ = SubjectPublicKeyInfo::<Any, String>::from_der(&der_bytes)
        .map_err(|e| format!("spki from_der: {e}"))?;
    Ok(der_bytes)
}

fn register_from_pubkey_pem(user_id: &str, path: &str) -> Result<(AddResult, String), String> {
    let pem_bytes = std::fs::read(path).map_err(|e| format!("read: {e}"))?;
    let spki_der  = spki_der_from_pubkey_pem(&pem_bytes)?;
    let (res, fpr) = add_user_key(user_id, spki_der);
    Ok((res, hex::encode(fpr)))
}


fn get_user_key(user_id: &str) -> Option<UserKey> {
    USERS.lock().unwrap().get(user_id).cloned()
}



//현재 DPF에는 session 개념이 없으므로 기존 ID/PASSWORD에 추가해서 DB화 할것.
static STORE: Lazy<Mutex<HashMap<String, SessionRec>>> = Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Clone, Debug)]
struct SessionRec {
    challenge: Vec<u8>,
    expires_at: OffsetDateTime,
    user_id: String,
}

// ---- 요청/응답 모델 ----
#[derive(Deserialize)]
struct ChallengeReq {
    user_id: String,
}

#[derive(Serialize)]
struct ChallengeResp {
    session_id: String,
    challenge_b64: String,
    expires_at: String,
}

#[derive(Deserialize)]
struct VerifyReq {
    session_id: String,
    user_id: String,
    signature_b64: String,       // RequestSignAsync 결과 바이트
}

#[derive(Serialize)]
struct VerifyResp {
    ok: bool,
    error: Option<String>,
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/auth/challenge", post(issue_challenge))
        .route("/auth/verify", post(verify_signature))
        .with_state(()); // 빈 스테이트

    // Add key: DB에 추가할것.
    println!("Register pubkey");
    match register_from_pubkey_pem("sample_id", "ex.pem") {
        Ok((res, fpr_hex)) => match res {
            AddResult::Inserted => println!("등록 성공 신규 추가 지문 {}", fpr_hex),
            AddResult::Replaced => println!("등록 성공 기존 키 교체 지문 {}", fpr_hex),
        },
        Err(e) => eprintln!("등록 실패 {}", e),
    }

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    println!("listening on http://{}", addr);

    // axum 0.7 방식: TcpListener + axum::serve
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// 1) 챌린지 발급
async fn issue_challenge(
    State(_): State<()>,
    Json(req): Json<ChallengeReq>,
) -> Json<ChallengeResp> {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);

    let session_id = Uuid::new_v4().to_string();
    let expires = OffsetDateTime::now_utc() + Duration::seconds(120);

    STORE.lock().unwrap().insert(
        session_id.clone(),
        SessionRec {
            challenge: buf.to_vec(),
            expires_at: expires,
            user_id: req.user_id,
        },
    );

    Json(ChallengeResp {
        session_id,
        challenge_b64: B64.encode(&buf),
        expires_at: expires
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
    })
}

// 2) 서명 검증
// 저장된 공개키로만 검증(P-256 + SHA-256)
fn verify_with_stored_p256(user_key: &UserKey, msg: &[u8], sig_der: &[u8]) -> Result<(), String> {
    let vk = VerifyingKey::from_public_key_der(&user_key.spki_der)
        .map_err(|e| format!("load spki: {e}"))?;
    let sig = P256Signature::from_der(sig_der)
        .map_err(|_| "bad ECDSA DER signature".to_string())?;
    vk.verify(msg, &sig).map_err(|_| "ECDSA verify failed".to_string())
}

async fn verify_signature(
    State(_): State<()>,
    Json(req): Json<VerifyReq>,
) -> Json<VerifyResp> {
    // 1 세션 로드
    let rec = {
        let mut m = STORE.lock().unwrap();
        match m.remove(&req.session_id) {
            Some(r) => r,
            None => return Json(VerifyResp { ok: false, error: Some("invalid session".into()) }),
        }
    };
    if rec.expires_at < OffsetDateTime::now_utc() {
        return Json(VerifyResp { ok: false, error: Some("session expired".into()) });
    }

    // 2 사용자 공개키 로드
    let user_key = match get_user_key(&req.user_id) {
        Some(k) => k,
        None => return Json(VerifyResp { ok: false, error: Some("unknown user".into()) }),
    };

    // 3 서명 파싱
    let sig = match B64.decode(req.signature_b64.as_bytes()) {
        Ok(v) => v,
        Err(_) => return Json(VerifyResp { ok: false, error: Some("bad signature_b64".into()) }),
    };

    // 4 저장된 공개키로만 검증
    match verify_with_stored_p256(&user_key, &rec.challenge, &sig) {
        Ok(()) => Json(VerifyResp { ok: true, error: None }),
        Err(e) => Json(VerifyResp { ok: false, error: Some(e) }),
    }
}
