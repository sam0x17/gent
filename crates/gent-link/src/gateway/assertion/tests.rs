use super::*;
use serde_json::{Value, json};

pub(crate) const CLIENT: &str = "https://host.example/oauth/client.json";
pub(crate) const RESOURCE: &str = "https://node.example/mcp";
pub(crate) fn policy() -> Policy {
    let jwks: Jwks = serde_json::from_str(include_str!("test-jwks.json")).unwrap();
    Policy {
        client_id: CLIENT.into(),
        keys: jwks.keys,
    }
}
pub(crate) fn claims() -> Value {
    let now = crate::auth::now().unwrap();
    json!({"iss":CLIENT,"sub":CLIENT,"aud":"https://node.example/oauth/token",
        "iat":now,"exp":now+120,"jti":uuid::Uuid::new_v4().to_string()})
}
// Public, disposable test keys generated with OpenSSL genpkey RSA/2048 and
// pkcs8 -topk8 -nocrypt -outform DER. Never used outside synthetic fixtures.
pub(crate) fn sign(header: Value, claims: Value, second_key: bool) -> String {
    sign_raw(
        &serde_json::to_vec(&header).unwrap(),
        &serde_json::to_vec(&claims).unwrap(),
        second_key,
    )
}
fn sign_raw(header: &[u8], claims: &[u8], second_key: bool) -> String {
    let private: &[u8] = if second_key {
        include_bytes!("fixture-b.pk8")
    } else {
        include_bytes!("fixture-a.pk8")
    };
    let key = signature::RsaKeyPair::from_pkcs8(private).unwrap();
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(claims)
    );
    let mut sig = vec![0; key.public().modulus_len()];
    key.sign(
        &signature::RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        input.as_bytes(),
        &mut sig,
    )
    .unwrap();
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
}
pub(crate) fn token(claims: Value) -> String {
    sign(
        json!({"alg":"RS256","kid":"fixture-a","typ":"JWT"}),
        claims,
        false,
    )
}

#[test]
fn signed_assertions_require_pinned_key_identity_audience_and_short_lifetime() {
    let p = policy();
    p.validate().unwrap();
    let now = crate::auth::now().unwrap();
    let mut valid = claims();
    valid["iat"] = json!(now);
    valid["exp"] = json!(now + 120);
    let original = token(valid.clone());
    assert_eq!(p.verify(&original, RESOURCE, now).unwrap().0, valid["jti"]);
    for aud in [
        json!("https://node.example"),
        json!(["https://node.example/oauth/token"]),
    ] {
        let mut value = valid.clone();
        value["aud"] = aud;
        p.verify(&token(value), RESOURCE, now).unwrap();
    }
    p.verify(
        &sign(
            json!({"alg":"RS256","kid":"fixture-b"}),
            valid.clone(),
            true,
        ),
        RESOURCE,
        now,
    )
    .unwrap();
    for (field, value) in [
        ("iss", json!("https://evil.example/client.json")),
        ("sub", json!("other")),
        ("aud", json!(RESOURCE)),
        (
            "aud",
            json!(["https://node.example", "https://evil.example"]),
        ),
        ("aud", json!("https://node.example/oauth/token/")),
        ("exp", json!(now)),
        ("exp", json!(now + 301)),
        ("iat", json!(now + 31)),
        ("iat", json!(now + 120)),
        ("jti", json!("x\ny")),
        ("nbf", json!(now + 1)),
        ("jti", json!("")),
        ("jti", json!("x".repeat(129))),
    ] {
        let mut changed = valid.clone();
        changed[field] = value;
        assert!(
            p.verify(&token(changed), RESOURCE, now).is_err(),
            "accepted {field}"
        );
    }
    for field in ["iss", "sub", "aud", "exp", "iat", "jti"] {
        let mut changed = valid.clone();
        changed.as_object_mut().unwrap().remove(field);
        assert!(p.verify(&token(changed), RESOURCE, now).is_err());
    }
    for header in [
        json!({"alg":"none","kid":"fixture-a"}),
        json!({"alg":"HS256","kid":"fixture-a"}),
        json!({"alg":"RS512","kid":"fixture-a"}),
        json!({"alg":"RS256","kid":"unknown"}),
        json!({"alg":"RS256","kid":"fixture-a","jku":"https://evil.example/keys"}),
        json!({"alg":"RS256","kid":"fixture-a","jwk":{}}),
        json!({"alg":"RS256","kid":"fixture-a","crit":["exp"]}),
        json!({"alg":"RS256","kid":"fixture-a","b64":false}),
        json!({"alg":"RS256","kid":"fixture-a","typ":"other"}),
    ] {
        assert!(
            p.verify(&sign(header, valid.clone(), false), RESOURCE, now)
                .is_err()
        );
    }
    assert!(
        p.verify(
            &sign(json!({"alg":"RS256","kid":"fixture-a"}), valid, true),
            RESOURCE,
            now
        )
        .is_err()
    );
    assert!(p.verify(&(original.clone() + "="), RESOURCE, now).is_err());
    assert!(
        p.verify(&original, "https://elsewhere.example/mcp", now)
            .is_err()
    );
    assert!(p.verify(&"x".repeat(4097), RESOURCE, now).is_err());
}

#[test]
fn duplicate_signed_header_and_claim_fields_are_rejected() {
    let p = policy();
    let now = crate::auth::now().unwrap();
    let claims = serde_json::to_string(&claims()).unwrap();
    let header = br#"{"alg":"RS256","kid":"fixture-a"}"#;
    let duplicate_header = br#"{"alg":"RS256","kid":"fixture-a","kid":"fixture-a"}"#;
    assert!(
        p.verify(
            &sign_raw(duplicate_header, claims.as_bytes(), false),
            RESOURCE,
            now
        )
        .is_err()
    );
    let duplicate = format!("{{\"iss\":\"{CLIENT}\",{}", &claims[1..]);
    assert!(
        p.verify(
            &sign_raw(header, duplicate.as_bytes(), false),
            RESOURCE,
            now
        )
        .is_err()
    );
}

#[test]
fn jwks_are_bounded_public_rsa_signing_keys_with_unique_ids() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("jwks.json");
    let original: Value = serde_json::from_str(include_str!("test-jwks.json")).unwrap();
    std::fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();
    Policy::load(&path, CLIENT).unwrap();
    for id in [
        "http://host.example/client.json",
        "https://host.example/",
        "https://u@host.example/client.json",
        "https://host.example/client.json?q=1",
        "https://host.example/client.json#x",
    ] {
        assert!(Policy::load(&path, id).is_err());
    }
    for (field, value) in [
        ("kty", json!("oct")),
        ("alg", json!("HS256")),
        ("use", json!("enc")),
        ("key_ops", json!(["sign"])),
        ("kid", json!("")),
        ("kid", json!("fixture-b")),
        ("d", json!("private")),
        ("e", json!("Aw")),
        ("n", json!("AA")),
    ] {
        let mut changed = original.clone();
        changed["keys"][0][field] = value;
        std::fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(Policy::load(&path, CLIENT).is_err(), "accepted {field}");
    }
    for keys in [json!([]), json!(vec![original["keys"][0].clone(); 9])] {
        std::fs::write(&path, serde_json::to_vec(&json!({"keys":keys})).unwrap()).unwrap();
        assert!(Policy::load(&path, CLIENT).is_err());
    }
    std::fs::write(&path, vec![b' '; MAX_JWKS + 1]).unwrap();
    assert!(Policy::load(&path, CLIENT).is_err());
}
