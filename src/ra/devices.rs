//! Device entries in LDAP, owned by the RA and written with its service
//! account.
//!
//! A device is `cn=<id>,<devices DN>` with object classes `device` and
//! `managedDevice`. Each certificate issued to it is recorded as a
//! `deviceCertificate` value, `<serial hex> <expiry>`, so the RA knows which
//! serials to revoke and which certificate is the newest. Records are removed
//! once their certificate has expired.

use std::collections::HashSet;
use std::time::Duration;

use ldap3::{dn_escape, LdapConn, LdapConnSettings, LdapError, Mod, Scope, SearchEntry};

use super::certs::CertificateInfo;
use super::config::Config;
use crate::shared::device::{device_id, label_from_id, Device, Platform};

const TIMEOUT: Duration = Duration::from_secs(5);

/// LDAP result code for an add whose DN already exists.
const ENTRY_ALREADY_EXISTS: u32 = 68;

/// LDAP result code for an operation on a DN that does not exist.
const NO_SUCH_OBJECT: u32 = 32;

const ATTRIBUTES: [&str; 6] = ["deviceId", "description", "deviceType", "deviceZone", "deviceDisabled", "deviceCertificate"];

/// A certificate issued to a device.
#[derive(Clone, Debug, PartialEq)]
pub struct CertificateRecord {
    pub serial_hex: String,
    /// `YYYYMMDDHHMMSSZ`, which orders correctly as text.
    pub not_after: String,
}

impl CertificateRecord {
    fn parse(value: &str) -> Option<CertificateRecord> {
        let (serial_hex, not_after) = value.split_once(' ')?;
        Some(CertificateRecord { serial_hex: serial_hex.to_string(), not_after: not_after.to_string() })
    }

    fn value(&self) -> String {
        format!("{} {}", self.serial_hex, self.not_after)
    }
}

pub struct Record {
    pub device: Device,
    pub certificates: Vec<CertificateRecord>,
}

impl Record {
    /// The certificate with the latest expiry: the only one that may renew.
    pub fn newest_certificate(&self) -> Option<&CertificateRecord> {
        self.certificates.iter().max_by(|a, b| a.not_after.cmp(&b.not_after))
    }
}

pub enum Created {
    Created(Device),
    AlreadyExists,
}

pub enum Change {
    Done,
    NotFound,
}

pub fn list(config: &Config) -> Result<Vec<Device>, String> {
    let mut devices: Vec<Device> = search(config, &config.ldap_devices_dn, Scope::OneLevel)?
        .into_iter()
        .map(|record| record.device)
        .collect();
    devices.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(devices)
}

pub fn get(config: &Config, label: &str) -> Result<Option<Record>, String> {
    Ok(search(config, &device_dn(config, label), Scope::Base)?.pop())
}

/// Creates an enabled device entry. The caller validates every value.
pub fn create(
    config: &Config,
    label: &str,
    description: &str,
    platform: Platform,
    zone: &str,
    owner: &str,
) -> Result<Created, String> {
    let id = device_id(&config.device_domain, label);
    let owner_dn = format!("uid={},{}", dn_escape(owner), config.ldap_people_dn);

    let mut attrs = vec![
        ("objectClass", HashSet::from(["device", "managedDevice"])),
        ("cn", HashSet::from([id.as_str()])),
        ("deviceId", HashSet::from([id.as_str()])),
        ("deviceType", HashSet::from([platform.id()])),
        ("deviceZone", HashSet::from([zone])),
        ("deviceDisabled", HashSet::from(["FALSE"])),
        ("owner", HashSet::from([owner_dn.as_str()])),
    ];
    if !description.is_empty() {
        attrs.push(("description", HashSet::from([description])));
    }

    let mut ldap = connect(config)?;
    let result = ldap.with_timeout(TIMEOUT).add(&device_dn(config, label), attrs);
    let _ = ldap.unbind();

    match result.map(|result| result.success()) {
        Ok(Ok(_)) => Ok(Created::Created(Device {
            id: id.clone(),
            label: label.to_string(),
            description: description.to_string(),
            platform: platform.id().to_string(),
            zone: zone.to_string(),
            disabled: false,
            certificate_expires: None,
        })),
        Ok(Err(LdapError::LdapResult { result })) if result.rc == ENTRY_ALREADY_EXISTS => Ok(Created::AlreadyExists),
        Ok(Err(err)) | Err(err) => Err(format!("adding {id} failed: {err}")),
    }
}

pub fn set_disabled(config: &Config, label: &str, disabled: bool) -> Result<Change, String> {
    let value = if disabled { "TRUE" } else { "FALSE" };
    modify(config, label, vec![Mod::Replace("deviceDisabled", HashSet::from([value]))])
}

pub fn delete(config: &Config, label: &str) -> Result<Change, String> {
    let mut ldap = connect(config)?;
    let result = ldap.with_timeout(TIMEOUT).delete(&device_dn(config, label));
    let _ = ldap.unbind();
    change_outcome(result, &format!("deleting {label}"))
}

/// Records a newly issued certificate, and forgets certificates that have
/// expired by `now` (`YYYYMMDDHHMMSSZ`).
pub fn record_certificate(
    config: &Config,
    record: &Record,
    certificate: &CertificateInfo,
    now: &str,
) -> Result<Change, String> {
    let new = CertificateRecord {
        serial_hex: certificate.serial_hex.clone(),
        not_after: certificate.not_after.clone(),
    }
    .value();
    let expired: Vec<String> = record
        .certificates
        .iter()
        .filter(|existing| existing.not_after.as_str() <= now)
        .map(CertificateRecord::value)
        .collect();

    let mut mods = vec![Mod::Add("deviceCertificate".to_string(), HashSet::from([new]))];
    if !expired.is_empty() {
        mods.push(Mod::Delete("deviceCertificate".to_string(), expired.into_iter().collect()));
    }
    modify(config, &record.device.label, mods)
}

fn modify<S: AsRef<[u8]> + Eq + std::hash::Hash>(config: &Config, label: &str, mods: Vec<Mod<S>>) -> Result<Change, String> {
    let mut ldap = connect(config)?;
    let result = ldap.with_timeout(TIMEOUT).modify(&device_dn(config, label), mods);
    let _ = ldap.unbind();
    change_outcome(result, &format!("modifying {label}"))
}

fn change_outcome(result: ldap3::result::Result<ldap3::LdapResult>, action: &str) -> Result<Change, String> {
    match result.map(|result| result.success()) {
        Ok(Ok(_)) => Ok(Change::Done),
        Ok(Err(LdapError::LdapResult { result })) if result.rc == NO_SUCH_OBJECT => Ok(Change::NotFound),
        Ok(Err(err)) | Err(err) => Err(format!("{action} failed: {err}")),
    }
}

fn device_dn(config: &Config, label: &str) -> String {
    format!("cn={},{}", dn_escape(device_id(&config.device_domain, label)), config.ldap_devices_dn)
}

fn search(config: &Config, base: &str, scope: Scope) -> Result<Vec<Record>, String> {
    let mut ldap = connect(config)?;
    let result = ldap
        .with_timeout(TIMEOUT)
        .search(base, scope, "(objectClass=managedDevice)", ATTRIBUTES.to_vec())
        .and_then(|result| result.success());
    let _ = ldap.unbind();

    let entries = match result {
        Ok((entries, _)) => entries,
        Err(LdapError::LdapResult { result }) if result.rc == NO_SUCH_OBJECT => Vec::new(),
        Err(err) => return Err(format!("device search failed: {err}")),
    };

    Ok(entries
        .into_iter()
        .map(SearchEntry::construct)
        .filter_map(|entry| {
            let first = |name: &str| entry.attrs.get(name).and_then(|v| v.first()).cloned().unwrap_or_default();
            let id = first("deviceId");
            let label = label_from_id(&config.device_domain, &id)?.to_string();
            let certificates: Vec<CertificateRecord> = entry
                .attrs
                .get("deviceCertificate")
                .map(|values| values.iter().filter_map(|value| CertificateRecord::parse(value)).collect())
                .unwrap_or_default();
            let certificate_expires = certificates.iter().map(|c| c.not_after.clone()).max();
            Some(Record {
                device: Device {
                    id,
                    label,
                    description: first("description"),
                    platform: first("deviceType"),
                    zone: first("deviceZone"),
                    disabled: first("deviceDisabled").eq_ignore_ascii_case("TRUE"),
                    certificate_expires,
                },
                certificates,
            })
        })
        .collect())
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
    fn certificate_records_round_trip() {
        let record = CertificateRecord { serial_hex: "0abc".into(), not_after: "20261026141431Z".into() };
        assert_eq!(record.value(), "0abc 20261026141431Z");
        assert_eq!(CertificateRecord::parse(&record.value()), Some(record));
        assert_eq!(CertificateRecord::parse("no-space"), None);
    }

    #[test]
    fn newest_certificate_has_the_latest_expiry() {
        let record = Record {
            device: Device {
                id: "tv.device.example.home.arpa".into(),
                label: "tv".into(),
                description: String::new(),
                platform: "linux".into(),
                zone: "trusted".into(),
                disabled: false,
                certificate_expires: None,
            },
            certificates: vec![
                CertificateRecord { serial_hex: "01".into(), not_after: "20261026000000Z".into() },
                CertificateRecord { serial_hex: "02".into(), not_after: "20261116000000Z".into() },
            ],
        };
        assert_eq!(record.newest_certificate().unwrap().serial_hex, "02");
    }
}
