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

#[cfg(test)]
mod tests {
    use super::parse_zones;

    #[test]
    fn parses_zone_lists() {
        assert_eq!(parse_zones("trusted, quarantine").unwrap(), ["trusted", "quarantine"]);
        assert!(parse_zones("trusted,").is_err());
        assert!(parse_zones("Trusted").is_err());
        assert!(parse_zones("a b").is_err());
    }
}
