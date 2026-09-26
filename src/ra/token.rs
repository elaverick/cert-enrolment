//! step-ca single-use tokens.
//!
//! The RA obtains a device certificate by sending a CSR and a sign token to
//! step-ca's `/1.0/sign`, and revokes one by sending its serial and a revoke
//! token to `/1.0/revoke`. Tokens are JWTs signed (ES256) with the private
//! key of a step-ca JWK provisioner. A sign token names exactly one device,
//! so step-ca will only issue a certificate for that name; a revoke token
//! names exactly one serial. Each token's `jti` makes it single-use; step-ca
//! records spent tokens in its database.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{json, Value};

use crate::shared::random::random_token;

pub struct Provisioner {
    /// Provisioner name, the token issuer.
    name: String,
    /// Key id, which step-ca uses to find the provisioner.
    kid: String,
    /// step-ca's base URL; token audiences are endpoints under it.
    ca_url: String,
    key: SigningKey,
}

/// How long a token stays usable. The RA uses each token at once.
const LIFETIME: Duration = Duration::from_secs(60);

impl Provisioner {
    /// Loads a private EC P-256 JWK, as produced by `step crypto jwk create`,
    /// and checks that its private and public parts belong together.
    pub fn new(ca_url: &str, name: &str, jwk: &str) -> Result<Provisioner, String> {
        let jwk: Value = serde_json::from_str(jwk).map_err(|err| format!("provisioner key is not JSON: {err}"))?;
        let field = |name: &str| {
            jwk.get(name)
                .and_then(Value::as_str)
                .ok_or(format!("provisioner key has no \"{name}\""))
        };

        if field("kty")? != "EC" || field("crv")? != "P-256" {
            return Err("provisioner key must be an EC P-256 JWK".to_string());
        }

        let decode = |name: &str| {
            URL_SAFE_NO_PAD
                .decode(field(name)?)
                .map_err(|_| format!("provisioner key \"{name}\" is not base64url"))
        };

        let key = SigningKey::from_slice(&decode("d")?).map_err(|_| "provisioner key \"d\" is not a valid P-256 key")?;

        let mut public = vec![0x04];
        public.extend(decode("x")?);
        public.extend(decode("y")?);
        if key.verifying_key().to_sec1_bytes().as_ref() != public.as_slice() {
            return Err("provisioner key \"x\"/\"y\" do not match \"d\"".to_string());
        }

        Ok(Provisioner {
            name: name.to_string(),
            kid: field("kid")?.to_string(),
            ca_url: ca_url.trim_end_matches('/').to_string(),
            key,
        })
    }

    /// A token that lets the holder obtain one certificate for `device_id`.
    pub fn sign_token(&self, device_id: &str) -> Result<String, String> {
        self.token("/1.0/sign", device_id, Some(device_id), LIFETIME)
    }

    /// A token that lets the holder revoke the certificate with this serial
    /// (in decimal, as step-ca identifies certificates).
    pub fn revoke_token(&self, serial_decimal: &str) -> Result<String, String> {
        self.token("/1.0/revoke", serial_decimal, None, LIFETIME)
    }

    fn token(&self, endpoint: &str, subject: &str, san: Option<&str>, lifetime: Duration) -> Result<String, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before 1970")?
            .as_secs();

        let header = json!({ "alg": "ES256", "typ": "JWT", "kid": self.kid });
        let mut claims = json!({
            "iss": self.name,
            "aud": format!("{}{endpoint}", self.ca_url),
            "sub": subject,
            "iat": now,
            "nbf": now,
            "exp": now + lifetime.as_secs(),
            "jti": random_token()?,
        });
        if let Some(san) = san {
            claims["sans"] = json!([san]);
        }

        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature: Signature = self.key.sign(signing_input.as_bytes());

        Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::VerifyingKey;

    /// A fixed test key: d = 1..=32, never used outside tests.
    fn test_jwk() -> String {
        let d: Vec<u8> = (1..=32).collect();
        let key = SigningKey::from_slice(&d).unwrap();
        let point = key.verifying_key().to_sec1_bytes();
        json!({
            "kty": "EC",
            "crv": "P-256",
            "kid": "test-kid",
            "d": URL_SAFE_NO_PAD.encode(&d),
            "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&point[33..65]),
        })
        .to_string()
    }

    fn decode_part(part: &str) -> Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
    }

    /// Checks the signature and returns the claims.
    fn verified_claims(provisioner: &Provisioner, token: &str) -> Value {
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header = decode_part(parts[0]);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "test-kid");

        let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
        VerifyingKey::from(&provisioner.key)
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .expect("signature verifies");

        decode_part(parts[1])
    }

    #[test]
    fn sign_tokens_are_bound_to_one_device() {
        let provisioner = Provisioner::new("https://ca.example.home.arpa/", "cert-enrolment", &test_jwk()).unwrap();
        let claims = verified_claims(&provisioner, &provisioner.sign_token("laptop.device.example.home.arpa").unwrap());

        assert_eq!(claims["iss"], "cert-enrolment");
        assert_eq!(claims["aud"], "https://ca.example.home.arpa/1.0/sign");
        assert_eq!(claims["sub"], "laptop.device.example.home.arpa");
        assert_eq!(claims["sans"], json!(["laptop.device.example.home.arpa"]));
        assert_eq!(claims["exp"].as_u64().unwrap() - claims["nbf"].as_u64().unwrap(), 60);
        assert_eq!(claims["jti"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn revoke_tokens_name_one_serial() {
        let provisioner = Provisioner::new("https://ca.example.home.arpa", "cert-enrolment", &test_jwk()).unwrap();
        let claims = verified_claims(&provisioner, &provisioner.revoke_token("123456789").unwrap());

        assert_eq!(claims["aud"], "https://ca.example.home.arpa/1.0/revoke");
        assert_eq!(claims["sub"], "123456789");
        assert!(claims.get("sans").is_none());
    }

    #[test]
    fn each_token_is_unique() {
        let provisioner = Provisioner::new("https://ca", "p", &test_jwk()).unwrap();
        let a = provisioner.sign_token("a.device").unwrap();
        let b = provisioner.sign_token("a.device").unwrap();
        assert_ne!(decode_part(a.split('.').nth(1).unwrap())["jti"], decode_part(b.split('.').nth(1).unwrap())["jti"]);
    }

    #[test]
    fn rejects_malformed_or_mismatched_keys() {
        assert!(Provisioner::new("https://ca", "p", "not json").is_err());
        assert!(Provisioner::new("https://ca", "p", r#"{"kty":"RSA"}"#).is_err());

        let mut mismatched: Value = serde_json::from_str(&test_jwk()).unwrap();
        mismatched["d"] = json!(URL_SAFE_NO_PAD.encode([7u8; 32]));
        assert!(Provisioner::new("https://ca", "p", &mismatched.to_string()).is_err());

        let mut public_only: Value = serde_json::from_str(&test_jwk()).unwrap();
        public_only.as_object_mut().unwrap().remove("d");
        assert!(Provisioner::new("https://ca", "p", &public_only.to_string()).is_err());
    }
}
