//! The portal's calls to the RA API.
//!
//! The RA owns device records; the portal asks it to list, register,
//! disable, enable and delete devices, and for enrolment codes. Every call
//! carries the RA API key and names the signed-in user for auditing.

use std::time::Duration;

use serde_json::{json, Value};
use ureq::Agent;

use crate::shared::device::Device;

const TIMEOUT: Duration = Duration::from_secs(30);

pub enum RaError {
    /// The RA refused the request; `message` is meant for people.
    Rejected { status: u16, message: String },
    /// The RA could not be reached, or its answer could not be read.
    Unavailable(String),
}

pub struct RaClient {
    agent: Agent,
    base_url: String,
    api_key: String,
}

impl RaClient {
    pub fn new(base_url: &str, api_key: &str) -> RaClient {
        let agent = Agent::config_builder()
            .timeout_global(Some(TIMEOUT))
            .http_status_as_error(false)
            .build()
            .into();
        RaClient { agent, base_url: base_url.trim_end_matches('/').to_string(), api_key: api_key.to_string() }
    }

    pub fn list(&self, actor: &str) -> Result<Vec<Device>, RaError> {
        let answer = self.call("GET", "/api/devices", actor, None)?;
        answer
            .get("devices")
            .and_then(Value::as_array)
            .map(|devices| devices.iter().filter_map(Device::from_json).collect())
            .ok_or_else(|| RaError::Unavailable("the RA returned no device list".to_string()))
    }

    /// `None` if the device is not registered.
    pub fn get(&self, actor: &str, label: &str) -> Result<Option<Device>, RaError> {
        match self.call("GET", &format!("/api/devices/{label}"), actor, None) {
            Ok(answer) => Device::from_json(&answer)
                .map(Some)
                .ok_or_else(|| RaError::Unavailable("the RA returned an unreadable device".to_string())),
            Err(RaError::Rejected { status: 404, .. }) => Ok(None),
            Err(err) => Err(err),
        }
    }

    pub fn create(&self, actor: &str, label: &str, description: &str, platform: &str, zone: &str) -> Result<Device, RaError> {
        let body = json!({ "label": label, "description": description, "platform": platform, "zone": zone });
        let answer = self.call("POST", "/api/devices", actor, Some(body))?;
        Device::from_json(&answer).ok_or_else(|| RaError::Unavailable("the RA returned an unreadable device".to_string()))
    }

    pub fn set_disabled(&self, actor: &str, label: &str, disabled: bool) -> Result<(), RaError> {
        let action = if disabled { "disable" } else { "enable" };
        self.call("POST", &format!("/api/devices/{label}/{action}"), actor, Some(json!({}))).map(|_| ())
    }

    pub fn delete(&self, actor: &str, label: &str) -> Result<(), RaError> {
        self.call("DELETE", &format!("/api/devices/{label}"), actor, None).map(|_| ())
    }

    pub fn enrolment_code(&self, actor: &str, label: &str) -> Result<String, RaError> {
        let answer = self.call("POST", &format!("/api/devices/{label}/enrolment-code"), actor, Some(json!({})))?;
        answer
            .get("code")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| RaError::Unavailable("the RA returned no enrolment code".to_string()))
    }

    fn call(&self, method: &str, path: &str, actor: &str, body: Option<Value>) -> Result<Value, RaError> {
        let url = format!("{}{path}", self.base_url);
        let authorization = format!("Bearer {}", self.api_key);
        let result = match (method, body) {
            ("GET", _) => self.agent.get(&url).header("Authorization", &authorization).header("X-Actor", actor).call(),
            ("DELETE", _) => self.agent.delete(&url).header("Authorization", &authorization).header("X-Actor", actor).call(),
            (_, body) => self
                .agent
                .post(&url)
                .header("Authorization", &authorization)
                .header("X-Actor", actor)
                .header("Content-Type", "application/json")
                .send(body.unwrap_or(Value::Null).to_string()),
        };
        let mut response = result.map_err(|err| RaError::Unavailable(format!("cannot reach the RA: {err}")))?;

        let status = response.status().as_u16();
        let text = response
            .body_mut()
            .read_to_string()
            .map_err(|err| RaError::Unavailable(format!("unreadable answer from the RA: {err}")))?;
        let answer: Value = if text.is_empty() { Value::Null } else { serde_json::from_str(&text).unwrap_or(Value::Null) };

        if (200..300).contains(&status) {
            Ok(answer)
        } else {
            let message = answer.get("error").and_then(Value::as_str).unwrap_or("The RA refused the request.").to_string();
            Err(RaError::Rejected { status, message })
        }
    }
}
