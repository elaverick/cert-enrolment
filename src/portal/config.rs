//! Portal configuration from environment variables.
//!
//! The portal holds no signing keys and no LDAP service account: users sign
//! in by binding to LDAP as themselves, and everything about devices goes
//! through the RA.

use std::env;
use std::time::Duration;

use crate::shared::settings::{
    certificate_file, listen_address, parse_zones, required, secret_file, valid_ca_url, valid_host_name, valid_ssid,
};

const DEFAULT_SESSION_MINUTES: u64 = 30;

pub struct Config {
    /// Address and port to listen on (plain HTTP; a reverse proxy terminates
    /// TLS).
    pub listen: String,
    /// LDAP server, which must use ldaps://. The CA used to verify it is
    /// taken from SSL_CERT_FILE.
    pub ldap_url: String,
    /// Container of user entries; users bind as uid=<name>,<people_dn>.
    pub ldap_people_dn: String,
    /// posixGroup whose memberUid values may enrol devices.
    pub ldap_enrollers_group_dn: String,
    /// The RA's API, as the portal reaches it (normally over loopback).
    pub ra_url: String,
    pub ra_api_key: String,
    /// The RA as devices reach it; written into enrolment scripts.
    pub ra_public_url: String,
    /// Device identities are <label>.<device_domain>.
    pub device_domain: String,
    /// Network zones a device may be placed in; the first is the default.
    pub device_zones: Vec<String>,
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

        let ra_url = required("CERT_ENROLMENT_RA_URL")?.trim_end_matches('/').to_string();
        if !(ra_url.starts_with("http://") || ra_url.starts_with("https://")) {
            return Err("CERT_ENROLMENT_RA_URL must be an http:// or https:// URL".to_string());
        }

        // These values are written into generated scripts, so they are held
        // to formats that need no escaping beyond quoting.
        let ra_public_url = required("CERT_ENROLMENT_RA_PUBLIC_URL")?.trim_end_matches('/').to_string();
        if !valid_ca_url(&ra_public_url) {
            return Err("CERT_ENROLMENT_RA_PUBLIC_URL must be an https:// URL with a host name and optional port".to_string());
        }

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

        Ok(Config {
            listen: listen_address("0.0.0.0:8080"),
            ldap_url,
            ldap_people_dn: required("CERT_ENROLMENT_LDAP_PEOPLE_DN")?,
            ldap_enrollers_group_dn: required("CERT_ENROLMENT_LDAP_ENROLLERS_GROUP_DN")?,
            ra_url,
            ra_api_key: secret_file("CERT_ENROLMENT_RA_API_KEY_FILE")?,
            ra_public_url,
            device_domain: required("CERT_ENROLMENT_DEVICE_DOMAIN")?.to_ascii_lowercase(),
            device_zones: parse_zones(&required("CERT_ENROLMENT_DEVICE_ZONES")?)?,
            wifi_ssid,
            radius_server_name,
            root_ca_pem: certificate_file(&root_ca_file)?,
            session_idle: Duration::from_secs(session_minutes * 60),
        })
    }
}
