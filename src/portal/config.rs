//! Configuration from environment variables.

use std::env;
use std::fs;
use std::time::Duration;

const DEFAULT_LISTEN: &str = "0.0.0.0:8080";
const DEFAULT_SESSION_MINUTES: u64 = 30;

pub struct Config {
    /// Address and port to listen on (plain HTTP; NGINX terminates TLS).
    pub listen: String,
    /// LDAP server, which must use ldaps://. The CA used to verify it is
    /// taken from SSL_CERT_FILE.
    pub ldap_url: String,
    /// Container of user entries; users bind as uid=<name>,<people_dn>.
    pub ldap_people_dn: String,
    /// posixGroup whose memberUid values may enrol devices.
    pub ldap_enrollers_group_dn: String,
    /// Service account used to read and write device entries.
    pub ldap_bind_dn: String,
    pub ldap_bind_password: String,
    /// Container of device entries.
    pub ldap_devices_dn: String,
    /// Device identities are <label>.<device_domain>.
    pub device_domain: String,
    /// Network zones a device may be placed in; the first is the default.
    pub device_zones: Vec<String>,
    /// step-ca base URL, as devices reach it.
    pub ca_url: String,
    /// JWK provisioner that signs enrolment tokens, and its private key.
    pub provisioner_name: String,
    pub provisioner_key: String,
    /// Trusted Wi-Fi network the enrolment scripts configure.
    pub wifi_ssid: String,
    /// Name in the RADIUS server certificate, which devices validate.
    pub radius_server_name: String,
    /// Root CA certificate (PEM) that devices are given to trust.
    pub root_ca_pem: String,
    /// Sessions expire after this long without a request.
    pub session_idle: Duration,
}

impl Config {
    pub fn from_env() -> Result<Config, String> {
        let ldap_url = required("CERT_ENROLMENT_LDAP_URL")?;
        if !ldap_url.starts_with("ldaps://") {
            return Err("CERT_ENROLMENT_LDAP_URL must use ldaps://".to_string());
        }

        let session_minutes = match env::var("CERT_ENROLMENT_SESSION_MINUTES") {
            Ok(value) => value
                .parse::<u64>()
                .ok()
                .filter(|minutes| *minutes > 0)
                .ok_or("CERT_ENROLMENT_SESSION_MINUTES must be a positive number")?,
            Err(_) => DEFAULT_SESSION_MINUTES,
        };

        let password_file = required("CERT_ENROLMENT_LDAP_BIND_PASSWORD_FILE")?;
        let ldap_bind_password = fs::read_to_string(&password_file)
            .map_err(|err| format!("cannot read {password_file}: {err}"))?
            .trim_end_matches(['\r', '\n'])
            .to_string();
        if ldap_bind_password.is_empty() {
            return Err(format!("{password_file} is empty"));
        }

        let device_zones = parse_zones(&required("CERT_ENROLMENT_DEVICE_ZONES")?)?;

        let ca_url = required("CERT_ENROLMENT_CA_URL")?.trim_end_matches('/').to_string();
        if !valid_ca_url(&ca_url) {
            return Err("CERT_ENROLMENT_CA_URL must be an https:// URL with a host name and optional port".to_string());
        }

        let key_file = required("CERT_ENROLMENT_PROVISIONER_KEY_FILE")?;
        let provisioner_key = fs::read_to_string(&key_file).map_err(|err| format!("cannot read {key_file}: {err}"))?;

        // These values are written into generated scripts, so they are held
        // to formats that need no escaping beyond quoting.
        let wifi_ssid = required("CERT_ENROLMENT_WIFI_SSID")?;
        if !valid_ssid(&wifi_ssid) {
            return Err("CERT_ENROLMENT_WIFI_SSID must be 1 to 32 printable ASCII characters".to_string());
        }

        let radius_server_name = required("CERT_ENROLMENT_RADIUS_SERVER_NAME")?.to_ascii_lowercase();
        if !valid_host_name(&radius_server_name) {
            return Err("CERT_ENROLMENT_RADIUS_SERVER_NAME must be a DNS name".to_string());
        }

        let root_ca_file = env::var("CERT_ENROLMENT_ROOT_CA_FILE")
            .or_else(|_| env::var("SSL_CERT_FILE"))
            .map_err(|_| "CERT_ENROLMENT_ROOT_CA_FILE or SSL_CERT_FILE must be set")?;
        let root_ca_pem = fs::read_to_string(&root_ca_file)
            .map_err(|err| format!("cannot read {root_ca_file}: {err}"))?
            .trim()
            .replace("\r\n", "\n");
        if !valid_certificate_pem(&root_ca_pem) {
            return Err(format!("{root_ca_file} must contain exactly one PEM certificate"));
        }

        Ok(Config {
            listen: env::var("CERT_ENROLMENT_LISTEN").unwrap_or_else(|_| DEFAULT_LISTEN.to_string()),
            ldap_url,
            ldap_people_dn: required("CERT_ENROLMENT_LDAP_PEOPLE_DN")?,
            ldap_enrollers_group_dn: required("CERT_ENROLMENT_LDAP_ENROLLERS_GROUP_DN")?,
            ldap_bind_dn: required("CERT_ENROLMENT_LDAP_BIND_DN")?,
            ldap_bind_password,
            ldap_devices_dn: required("CERT_ENROLMENT_LDAP_DEVICES_DN")?,
            device_domain: required("CERT_ENROLMENT_DEVICE_DOMAIN")?.to_ascii_lowercase(),
            device_zones,
            ca_url,
            provisioner_name: required("CERT_ENROLMENT_PROVISIONER")?,
            provisioner_key,
            wifi_ssid,
            radius_server_name,
            root_ca_pem,
            session_idle: Duration::from_secs(session_minutes * 60),
        })
    }
}

fn required(name: &str) -> Result<String, String> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(format!("{name} must be set")),
    }
}

/// Parses a comma-separated list of zone names, such as "trusted,quarantine".
fn parse_zones(value: &str) -> Result<Vec<String>, String> {
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
fn valid_ssid(ssid: &str) -> bool {
    (1..=32).contains(&ssid.len()) && ssid.bytes().all(|b| (0x20..0x7f).contains(&b))
}

/// `https://host[:port]`, which is written unescaped into scripts.
fn valid_ca_url(url: &str) -> bool {
    let Some(authority) = url.strip_prefix("https://") else {
        return false;
    };
    let (host, port) = authority.split_once(':').unwrap_or((authority, "443"));
    valid_host_name(host) && !port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit())
}

fn valid_host_name(name: &str) -> bool {
    name.len() <= 253
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// One PEM certificate, containing only base64 between its markers.
fn valid_certificate_pem(pem: &str) -> bool {
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
