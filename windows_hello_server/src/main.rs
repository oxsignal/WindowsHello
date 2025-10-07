use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use once_cell::sync::Lazy;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use spki::{AlgorithmIdentifierRef, ObjectIdentifier, SubjectPublicKeyInfoRef};
use std::{collections::HashMap, net::SocketAddr, sync::Mutex};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use rsa::signature::Verifier;
// 트레이트 임포트(반드시 필요)
use der::Decode;            // for SubjectPublicKeyInfoRef::from_der
use spki::DecodePublicKey;  // for from_public_key_der on p256/rsa types

// ---- 인메모리 세션 스토어 ----
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
    public_key_der_b64: String, // SPKI DER (클라의 RetrievePublicKeyWithBlobType 결과)
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
async fn verify_signature(
    State(_): State<()>,
    Json(req): Json<VerifyReq>,
) -> Json<VerifyResp> {
    // 세션 로드(1회성)
    let rec = {
        let mut m = STORE.lock().unwrap();
        match m.remove(&req.session_id) {
            Some(r) => r,
            None => {
                return Json(VerifyResp {
                    ok: false,
                    error: Some("invalid session".into()),
                })
            }
        }
    };
    if rec.expires_at < OffsetDateTime::now_utc() {
        return Json(VerifyResp {
            ok: false,
            error: Some("session expired".into()),
        });
    }

    // 입력 파싱
    let spki_der = match B64.decode(req.public_key_der_b64.as_bytes()) {
        Ok(v) => v,
        Err(_) => {
            return Json(VerifyResp {
                ok: false,
                error: Some("bad public_key_der_b64".into()),
            })
        }
    };
    let sig = match B64.decode(req.signature_b64.as_bytes()) {
        Ok(v) => v,
        Err(_) => {
            return Json(VerifyResp {
                ok: false,
                error: Some("bad signature_b64".into()),
            })
        }
    };

    // 검증
    match verify_spki_signature(&spki_der, &rec.challenge, &sig) {
        Ok(()) => Json(VerifyResp { ok: true, error: None }),
        Err(e) => Json(VerifyResp {
            ok: false,
            error: Some(e),
        }),
    }
}

// ---- 서명 검증 로직 (RustCrypto) ----
fn verify_spki_signature(spki_der: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<(), String> {
    // SPKI 파싱
    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| format!("SPKI parse error: {e}"))?;
    let alg: AlgorithmIdentifierRef<'_> = spki.algorithm;

    // 알고리즘 식별자 OID
    const OID_ID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
    const OID_SECP256R1: &str = "1.2.840.10045.3.1.7";
    const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
    const OID_RSASSA_PSS: &str = "1.2.840.113549.1.1.10";

    let oid = alg.oid;

    // 1) ECDSA P-256 + SHA-256
    if oid == ObjectIdentifier::new_unwrap(OID_ID_EC_PUBLIC_KEY) {
        // curve OID 확인 (parameters는 AnyRef이므로 OID로 변환)
        let params = alg.parameters.ok_or("EC params missing")?;
        let curve_oid =
            ObjectIdentifier::try_from(params).map_err(|_| "EC params not an OID")?;
        if curve_oid == ObjectIdentifier::new_unwrap(OID_SECP256R1) {
            use p256::ecdsa::{Signature as P256Signature, VerifyingKey};
            use p256::PublicKey;

            // 전체 SPKI DER로부터 P-256 공개키 로드 (DecodePublicKey 필요)
            let pkey =
                PublicKey::from_public_key_der(spki_der).map_err(|e| format!("p256 load: {e}"))?;
            let vk = VerifyingKey::from(pkey);

            // Windows Hello 서명은 보통 DER(r,s)
            let sig = P256Signature::from_der(sig_bytes)
                .map_err(|_| "expecting ECDSA DER signature (r,s)")?;
            vk.verify(msg, &sig)
                .map_err(|_| "ECDSA verify failed".to_string())?;
            return Ok(());
        }
        return Err("Unsupported EC curve (expect secp256r1)".into());
    }

    // 2) RSA PKCS#1 v1.5 + SHA-256
    if oid == ObjectIdentifier::new_unwrap(OID_RSA_ENCRYPTION) {
        use rsa::pkcs1v15::{Signature as RsaPkcs1Sig, VerifyingKey};
        use rsa::RsaPublicKey;
        use sha2::Sha256;

        // SPKI DER에서 RSA 공개키 로드 (DecodePublicKey 필요)
        let rsa_pub =
            RsaPublicKey::from_public_key_der(spki_der).map_err(|e| format!("RSA load: {e}"))?;
        let vk = VerifyingKey::<Sha256>::new(rsa_pub);

        let sig = RsaPkcs1Sig::try_from(sig_bytes).map_err(|_| "bad RSA PKCS#1 v1.5 sig")?;
        vk.verify(msg, &sig)
            .map_err(|_| "RSA PKCS#1 v1.5 verify failed".to_string())?;
        return Ok(());
    }

    // 3) RSA-PSS + SHA-256
    if oid == ObjectIdentifier::new_unwrap(OID_RSASSA_PSS) {
        use rsa::pss::{Signature as RsaPssSig, VerifyingKey};
        use rsa::RsaPublicKey;
        use sha2::Sha256;

        let rsa_pub =
            RsaPublicKey::from_public_key_der(spki_der).map_err(|e| format!("RSA load: {e}"))?;
        let vk = VerifyingKey::<Sha256>::new(rsa_pub);

        let sig = RsaPssSig::try_from(sig_bytes).map_err(|_| "bad RSA-PSS sig")?;
        vk.verify(msg, &sig)
            .map_err(|_| "RSA-PSS verify failed".to_string())?;
        return Ok(());
    }

    Err("Unsupported key algorithm OID".into())
}
