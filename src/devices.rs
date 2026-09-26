//! Device entries in LDAP, read and written with the service account.
//!
//! A device is `cn=<id>,<devices_dn>` with object classes `device` and
//! `managedDevice`, where `<id>` is `<label>.<device_domain>`. The id is
//! both the certificate Common Name and `deviceId`, which FreeRADIUS matches.

use std::collections::HashSet;
use std::time::Duration;

use ldap3::{dn_escape, LdapConn, LdapConnSettings, LdapError, Mod, Scope, SearchEntry};

use crate::config::Config;

const TIMEOUT: Duration = Duration::from_secs(5);

/// LDAP result code for an add whose DN already exists.
const ENTRY_ALREADY_EXISTS: u32 = 68;

/// LDAP result code for an operation on a DN that does not exist.
const NO_SUCH_OBJECT: u32 = 32;

#[derive(Clone, Copy, PartialEq, Eq)]
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
            Platform::Ios => "iOS",
        }
    }

    pub fn from_id(id: &str) -> Option<Platform> {
        Platform::ALL.into_iter().find(|platform| platform.id() == id)
    }
}

pub struct Device {
    pub id: String,
    pub platform: String,
    pub zone: String,
    pub disabled: bool,
}

pub enum Registration {
    Registered(String),
    AlreadyExists(String),
}

/// A device label is a single DNS label, matching the CA policy wildcard
/// and the FreeRADIUS device identity check.
pub fn valid_label(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

pub fn device_id(config: &Config, label: &str) -> String {
    format!("{label}.{}", config.device_domain)
}

/// Returns the label of a well-formed device id in the device domain.
pub fn label_from_id<'a>(device_domain: &str, id: &'a str) -> Option<&'a str> {
    let label = id.strip_suffix(device_domain)?.strip_suffix('.')?;
    valid_label(label).then_some(label)
}

fn device_dn(config: &Config, label: &str) -> String {
    format!("cn={},{}", dn_escape(device_id(config, label)), config.ldap_devices_dn)
}

pub enum Change {
    Done,
    NotFound,
}

pub fn set_disabled(config: &Config, label: &str, disabled: bool) -> Result<Change, String> {
    let value = if disabled { "TRUE" } else { "FALSE" };
    let mods = vec![Mod::Replace("deviceDisabled", HashSet::from([value]))];

    let mut ldap = connect(config)?;
    let result = ldap.with_timeout(TIMEOUT).modify(&device_dn(config, label), mods);
    let _ = ldap.unbind();

    change_outcome(result, &format!("setting deviceDisabled={value} on {label}"))
}

pub fn delete(config: &Config, label: &str) -> Result<Change, String> {
    let mut ldap = connect(config)?;
    let result = ldap.with_timeout(TIMEOUT).delete(&device_dn(config, label));
    let _ = ldap.unbind();

    change_outcome(result, &format!("deleting {label}"))
}

fn change_outcome(result: ldap3::result::Result<ldap3::LdapResult>, action: &str) -> Result<Change, String> {
    match result.map(|result| result.success()) {
        Ok(Ok(_)) => Ok(Change::Done),
        Ok(Err(LdapError::LdapResult { result })) if result.rc == NO_SUCH_OBJECT => Ok(Change::NotFound),
        Ok(Err(err)) | Err(err) => Err(format!("{action} failed: {err}")),
    }
}

pub fn list(config: &Config) -> Result<Vec<Device>, String> {
    let mut ldap = connect(config)?;

    let result = ldap
        .with_timeout(TIMEOUT)
        .search(
            &config.ldap_devices_dn,
            Scope::OneLevel,
            "(objectClass=managedDevice)",
            vec!["deviceId", "deviceType", "deviceZone", "deviceDisabled"],
        )
        .and_then(|result| result.success())
        .map_err(|err| format!("device search failed: {err}"));

    let _ = ldap.unbind();
    let (entries, _) = result?;

    let mut devices: Vec<Device> = entries
        .into_iter()
        .map(SearchEntry::construct)
        .map(|entry| {
            let first = |name: &str| entry.attrs.get(name).and_then(|v| v.first()).cloned().unwrap_or_default();
            Device {
                id: first("deviceId"),
                platform: first("deviceType"),
                zone: first("deviceZone"),
                disabled: first("deviceDisabled").eq_ignore_ascii_case("TRUE"),
            }
        })
        .filter(|device| !device.id.is_empty())
        .collect();

    devices.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(devices)
}

/// Creates an enabled device entry. The caller validates the label and zone.
pub fn register(
    config: &Config,
    label: &str,
    platform: Platform,
    zone: &str,
    owner: &str,
) -> Result<Registration, String> {
    let id = device_id(config, label);
    let dn = device_dn(config, label);
    let owner_dn = format!("uid={},{}", dn_escape(owner), config.ldap_people_dn);

    let attrs = vec![
        ("objectClass", HashSet::from(["device", "managedDevice"])),
        ("cn", HashSet::from([id.as_str()])),
        ("deviceId", HashSet::from([id.as_str()])),
        ("deviceType", HashSet::from([platform.id()])),
        ("deviceZone", HashSet::from([zone])),
        ("deviceDisabled", HashSet::from(["FALSE"])),
        ("owner", HashSet::from([owner_dn.as_str()])),
    ];

    let mut ldap = connect(config)?;
    let result = ldap.with_timeout(TIMEOUT).add(&dn, attrs);
    let _ = ldap.unbind();

    match result.map(|result| result.success()) {
        Ok(Ok(_)) => Ok(Registration::Registered(id)),
        Ok(Err(LdapError::LdapResult { result })) if result.rc == ENTRY_ALREADY_EXISTS => {
            Ok(Registration::AlreadyExists(id))
        }
        Ok(Err(err)) | Err(err) => Err(format!("adding {id} failed: {err}")),
    }
}

fn connect(config: &Config) -> Result<LdapConn, String> {
    let settings = LdapConnSettings::new().set_conn_timeout(TIMEOUT);
    let mut ldap = LdapConn::with_settings(settings, &config.ldap_url)
        .map_err(|err| format!("cannot connect to {}: {err}", config.ldap_url))?;

    ldap.with_timeout(TIMEOUT)
        .simple_bind(&config.ldap_bind_dn, &config.ldap_bind_password)
        .and_then(|result| result.success())
        .map_err(|err| format!("service account bind failed: {err}"))?;

    Ok(ldap)
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
    fn extracts_labels_from_device_ids() {
        let domain = "device.laverick.home.arpa";
        assert_eq!(label_from_id(domain, "ed-laptop.device.laverick.home.arpa"), Some("ed-laptop"));
        for id in [
            "device.laverick.home.arpa",
            ".device.laverick.home.arpa",
            "a.b.device.laverick.home.arpa",
            "ed-laptopdevice.laverick.home.arpa",
            "ed-laptop.other.home.arpa",
            "Ed.device.laverick.home.arpa",
        ] {
            assert_eq!(label_from_id(domain, id), None, "{id:?} should be rejected");
        }
    }

    #[test]
    fn platform_ids_round_trip() {
        for platform in Platform::ALL {
            assert!(Platform::from_id(platform.id()) == Some(platform));
        }
        assert!(Platform::from_id("android").is_none());
    }
}
