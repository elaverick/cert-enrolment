//! Reading and checking settings from environment variables, shared by
//! both roles.

use std::env;
use std::fs;


/// Reads a secret from a file (for example a container secret), without its
/// trailing line break.
pub fn secret_file(variable: &str) -> Result<String, String> {
    let path = required(variable)?;
    let secret = fs::read_to_string(&path)
        .map_err(|err| format!("cannot read {path}: {err}"))?
        .trim_end_matches(['\r', '\n'])
        .to_string();
    if secret.is_empty() {
        return Err(format!("{path} is empty"));
    }
    Ok(secret)
}

/// Reads a file holding exactly one PEM certificate.
pub fn certificate_file(path: &str) -> Result<String, String> {
    let pem = fs::read_to_string(path)
        .map_err(|err| format!("cannot read {path}: {err}"))?
        .trim()
        .replace("\r\n", "\n");
    if !valid_certificate_pem(&pem) {
        return Err(format!("{path} must contain exactly one PEM certificate"));
    }
    Ok(pem)
}

pub fn listen_address(default: &str) -> String {
    env::var("CERT_ENROLMENT_LISTEN").unwrap_or_else(|_| default.to_string())
}

pub fn required(name: &str) -> Result<String, String> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(format!("{name} must be set")),
    }
}

/// Parses a comma-separated list of zone names, such as "trusted,quarantine".
pub fn parse_zones(value: &str) -> Result<Vec<String>, String> {
    let zones: Vec<String> = value.split(',').map(|zone| zone.trim().to_string()).collect();

    let valid = zones.iter().all(|zone| {
        !zone.is_empty() && zone.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    if !valid {
        return Err("CERT_ENROLMENT_DEVICE_ZONES must be a comma-separated list of lowercase zone names".to_string());
    }

    Ok(zones)
}

/// SSIDs are up to 32 bytes. Printable ASCII keeps them safe to quote in
/// PowerShell and shell scripts and in XML.
pub fn valid_ssid(ssid: &str) -> bool {
    (1..=32).contains(&ssid.len()) && ssid.bytes().all(|b| (0x20..0x7f).contains(&b))
}

/// `https://host[:port]`, which is written unescaped into scripts.
pub fn valid_ca_url(url: &str) -> bool {
    let Some(authority) = url.strip_prefix("https://") else {
        return false;
    };
    let (host, port) = authority.split_once(':').unwrap_or((authority, "443"));
    valid_host_name(host) && !port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit())
}

pub fn valid_host_name(name: &str) -> bool {
    name.len() <= 253
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// One PEM certificate, containing only base64 between its markers.
pub fn valid_certificate_pem(pem: &str) -> bool {
    let Some(body) = pem
        .strip_prefix("-----BEGIN CERTIFICATE-----\n")
        .and_then(|rest| rest.strip_suffix("\n-----END CERTIFICATE-----"))
    else {
        return false;
    };
    !body.is_empty() && body.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/=\n".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_script_values() {
        assert!(valid_ssid("Laverick"));
        assert!(valid_ssid("Home Wi-Fi 'n' more"));
        assert!(!valid_ssid(""));
        assert!(!valid_ssid(&"a".repeat(33)));
        assert!(!valid_ssid("caf\u{e9}"));
        assert!(!valid_ssid("tab\there"));

        assert!(valid_ca_url("https://ca.example.home.arpa"));
        assert!(valid_ca_url("https://ca.example.home.arpa:9000"));
        assert!(!valid_ca_url("http://ca.example.home.arpa"));
        assert!(!valid_ca_url("https://ca.example.home.arpa/path"));
        assert!(!valid_ca_url("https://ca.example.home.arpa:9000'x"));

        assert!(valid_host_name("freeradius.example.home.arpa"));
        assert!(!valid_host_name("freeradius..example"));
        assert!(!valid_host_name("bad name.example"));
        assert!(!valid_host_name("-x.example"));

        assert!(valid_certificate_pem("-----BEGIN CERTIFICATE-----\nMIIB+/=\nAAAA\n-----END CERTIFICATE-----"));
        assert!(!valid_certificate_pem("-----BEGIN CERTIFICATE-----\nMII'B\n-----END CERTIFICATE-----"));
        assert!(!valid_certificate_pem(
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"
        ));
    }

    #[test]
    fn parses_zone_lists() {
        assert_eq!(parse_zones("trusted, quarantine").unwrap(), ["trusted", "quarantine"]);
        assert!(parse_zones("trusted,").is_err());
        assert!(parse_zones("Trusted").is_err());
        assert!(parse_zones("a b").is_err());
    }
}
