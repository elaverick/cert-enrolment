//! Calls to step-ca: signing certificate requests and revoking certificates.
//!
//! step-ca's TLS certificate is verified against the Root CA only.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use ureq::tls::{Certificate, RootCerts, TlsConfig};
use ureq::Agent;

const TIMEOUT: Duration = Duration::from_secs(10);

pub enum CaError {
    /// step-ca answered with an error.
    Refused { status: u16, message: String },
    /// step-ca could not be reached, or its answer could not be read.
    Unavailable(String),
}

impl std::fmt::Display for CaError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CaError::Refused { status, message } => write!(f, "step-ca refused the request (HTTP {status}): {message}"),
            CaError::Unavailable(reason) => write!(f, "step-ca is unavailable: {reason}"),
        }
    }
}

/// A certificate as step-ca returns it.
pub struct Issued {
    /// The device certificate, PEM.
    pub certificate: String,
    /// The intermediate CA, PEM.
    pub intermediate: String,
}

pub struct StepCa {
    agent: Agent,
    ca_url: String,
}

impl StepCa {
    pub fn new(ca_url: &str, root_ca_pem: &str) -> Result<StepCa, String> {
        let root = Certificate::from_pem(root_ca_pem.as_bytes())
            .map_err(|err| format!("cannot read the Root CA: {err}"))?
            .to_owned();
        let tls = TlsConfig::builder()
            .root_certs(RootCerts::Specific(Arc::new(vec![root])))
            .build();
        let agent = Agent::config_builder()
            .tls_config(tls)
            .timeout_global(Some(TIMEOUT))
            .http_status_as_error(false)
            .build()
            .into();

        Ok(StepCa { agent, ca_url: ca_url.trim_end_matches('/').to_string() })
    }

    /// Asks step-ca to sign a certificate request, authorised by a sign token.
    pub fn sign(&self, csr_pem: &str, token: &str) -> Result<Issued, CaError> {
        let answer = self.post("/1.0/sign", &json!({ "csr": csr_pem, "ott": token }))?;
        let text = |name: &str| answer.get(name).and_then(Value::as_str).map(str::to_string);
        match (text("crt"), text("ca")) {
            (Some(certificate), Some(intermediate)) => Ok(Issued { certificate, intermediate }),
            _ => Err(CaError::Unavailable("step-ca returned no certificate".to_string())),
        }
    }

    /// Passively revokes a certificate: step-ca records the serial and
    /// refuses to renew it. Revoking an already revoked serial succeeds.
    pub fn revoke(&self, serial_decimal: &str, token: &str, reason: &str) -> Result<(), CaError> {
        let body = json!({
            "serial": serial_decimal,
            "ott": token,
            "passive": true,
            "reasonCode": 0,
            "reason": reason,
        });
        match self.post("/1.0/revoke", &body) {
            Ok(_) => Ok(()),
            Err(CaError::Refused { message, .. }) if message.contains("already revoked") => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn post(&self, path: &str, body: &Value) -> Result<Value, CaError> {
        let mut response = self
            .agent
            .post(&format!("{}{path}", self.ca_url))
            .header("Content-Type", "application/json")
            .send(body.to_string())
            .map_err(|err| CaError::Unavailable(err.to_string()))?;

        let status = response.status().as_u16();
        let text = response
            .body_mut()
            .read_to_string()
            .map_err(|err| CaError::Unavailable(format!("unreadable answer: {err}")))?;
        let answer: Value = serde_json::from_str(&text).unwrap_or(Value::Null);

        if (200..300).contains(&status) {
            Ok(answer)
        } else {
            let message = answer.get("message").and_then(Value::as_str).unwrap_or(&text).to_string();
            Err(CaError::Refused { status, message })
        }
    }
}
