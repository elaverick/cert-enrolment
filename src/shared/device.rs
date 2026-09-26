//! The device model and its validation, shared by the portal and the RA.
//!
//! A device's identity is `<label>.<device domain>`: the certificate Common
//! Name, the LDAP `deviceId`, and what FreeRADIUS matches.

use serde_json::{json, Value};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Platform {
    Windows,
    Linux,
    Ios,
}

impl Platform {
    pub const ALL: [Platform; 3] = [Platform::Windows, Platform::Linux, Platform::Ios];

    /// Value stored in `deviceType`.
    pub fn id(self) -> &'static str {
        match self {
            Platform::Windows => "windows",
            Platform::Linux => "linux",
            Platform::Ios => "ios",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Platform::Windows => "Windows",
            Platform::Linux => "Linux",
            Platform::Ios => "iPhone / iPad",
        }
    }

    pub fn from_id(id: &str) -> Option<Platform> {
        Platform::ALL.into_iter().find(|platform| platform.id() == id)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Device {
    pub id: String,
    /// The single label before the device domain.
    pub label: String,
    /// Optional friendly description, e.g. "Edward's laptop".
    pub description: String,
    pub platform: String,
    pub zone: String,
    pub disabled: bool,
    /// Expiry of the device's newest certificate, as `YYYYMMDDHHMMSSZ`.
    pub certificate_expires: Option<String>,
}

impl Device {
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "label": self.label,
            "description": self.description,
            "platform": self.platform,
            "zone": self.zone,
            "disabled": self.disabled,
            "certificateExpires": self.certificate_expires,
        })
    }

    pub fn from_json(value: &Value) -> Option<Device> {
        let text = |name: &str| value.get(name).and_then(Value::as_str).map(str::to_string);
        Some(Device {
            id: text("id")?,
            label: text("label")?,
            description: text("description").unwrap_or_default(),
            platform: text("platform")?,
            zone: text("zone")?,
            disabled: value.get("disabled").and_then(Value::as_bool)?,
            certificate_expires: text("certificateExpires"),
        })
    }
}

/// A device label is a single DNS label, matching the CA policy wildcard
/// and the FreeRADIUS device identity check.
pub fn valid_label(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

/// Longest description accepted, in characters.
pub const DESCRIPTION_MAX: usize = 64;

/// A description is optional free text: no control characters, and short
/// enough to show in a list.
pub fn valid_description(description: &str) -> bool {
    description.chars().count() <= DESCRIPTION_MAX && !description.chars().any(char::is_control)
}

pub fn device_id(device_domain: &str, label: &str) -> String {
    format!("{label}.{device_domain}")
}

/// Returns the label of a well-formed device id in the device domain.
pub fn label_from_id<'a>(device_domain: &str, id: &'a str) -> Option<&'a str> {
    let label = id.strip_suffix(device_domain)?.strip_suffix('.')?;
    valid_label(label).then_some(label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_dns_labels() {
        for label in ["laptop", "ed-laptop-2", "a", &"a".repeat(63)] {
            assert!(valid_label(label), "{label:?} should be accepted");
        }
    }

    #[test]
    fn rejects_non_labels() {
        for label in ["", "-a", "a-", "Laptop", "a.b", "a_b", "a b", &"a".repeat(64)] {
            assert!(!valid_label(label), "{label:?} should be rejected");
        }
    }

    #[test]
    fn validates_descriptions() {
        assert!(valid_description(""));
        assert!(valid_description("Edward\u{2019}s laptop"));
        assert!(valid_description(&"é".repeat(DESCRIPTION_MAX)));
        assert!(!valid_description(&"a".repeat(DESCRIPTION_MAX + 1)));
        assert!(!valid_description("line\nbreak"));
        assert!(!valid_description("tab\there"));
    }

    #[test]
    fn extracts_labels_from_device_ids() {
        let domain = "device.example.home.arpa";
        assert_eq!(label_from_id(domain, "ed-laptop.device.example.home.arpa"), Some("ed-laptop"));
        for id in [
            "device.example.home.arpa",
            ".device.example.home.arpa",
            "a.b.device.example.home.arpa",
            "ed-laptopdevice.example.home.arpa",
            "ed-laptop.other.home.arpa",
            "Ed.device.example.home.arpa",
        ] {
            assert_eq!(label_from_id(domain, id), None, "{id:?} should be rejected");
        }
    }

    #[test]
    fn platform_ids_round_trip() {
        for platform in Platform::ALL {
            assert_eq!(Platform::from_id(platform.id()), Some(platform));
        }
        assert!(Platform::from_id("android").is_none());
    }

    #[test]
    fn devices_round_trip_through_json() {
        let device = Device {
            id: "tv.device.example.home.arpa".into(),
            label: "tv".into(),
            description: "Lounge TV".into(),
            platform: "linux".into(),
            zone: "trusted".into(),
            disabled: false,
            certificate_expires: Some("20261026141431Z".into()),
        };
        assert_eq!(Device::from_json(&device.to_json()), Some(device));
    }
}
