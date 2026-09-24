//! Configuration from environment variables.

use std::env;
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

        Ok(Config {
            listen: env::var("CERT_ENROLMENT_LISTEN").unwrap_or_else(|_| DEFAULT_LISTEN.to_string()),
            ldap_url,
            ldap_people_dn: required("CERT_ENROLMENT_LDAP_PEOPLE_DN")?,
            ldap_enrollers_group_dn: required("CERT_ENROLMENT_LDAP_ENROLLERS_GROUP_DN")?,
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
