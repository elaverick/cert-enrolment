//! RA configuration from environment variables.

use std::env;
use std::fs;

use crate::shared::settings::{
    certificate_file, listen_address, parse_zones, required, secret_file, valid_ca_url,
};

pub struct Config {
    /// Address and port to listen on (plain HTTP). A reverse proxy
    /// terminates TLS and verifies device client certificates in front of it.
    pub listen: String,
    /// LDAP server, which must use ldaps://, verified against the Root CA.
    pub ldap_url: String,
    /// Container of user entries; device owners are uid=<name>,<people_dn>.
    pub ldap_people_dn: String,
    /// Service account that reads and writes device entries.
    pub ldap_bind_dn: String,
    pub ldap_bind_password: String,
    /// Container of device entries.
    pub ldap_devices_dn: String,
    /// Device identities are <label>.<device_domain>.
    pub device_domain: String,
    /// Network zones a device may be placed in.
    pub device_zones: Vec<String>,
    /// step-ca base URL.
    pub ca_url: String,
    /// JWK provisioner whose private key signs step-ca tokens.
    pub provisioner_name: String,
    pub provisioner_key: String,
    /// Root CA certificate (PEM), trusted for step-ca's TLS.
    pub root_ca_pem: String,
    /// Shared secret the portal presents as a bearer token.
    pub api_key: String,
}

impl Config {
    pub fn from_env() -> Result<Config, String> {
        let ldap_url = required("CERT_ENROLMENT_LDAP_URL")?;
        if !ldap_url.starts_with("ldaps://") {
            return Err("CERT_ENROLMENT_LDAP_URL must use ldaps://".to_string());
        }

        let ca_url = required("CERT_ENROLMENT_CA_URL")?.trim_end_matches('/').to_string();
        if !valid_ca_url(&ca_url) {
            return Err("CERT_ENROLMENT_CA_URL must be an https:// URL with a host name and optional port".to_string());
        }

        let key_file = required("CERT_ENROLMENT_PROVISIONER_KEY_FILE")?;
        let provisioner_key = fs::read_to_string(&key_file).map_err(|err| format!("cannot read {key_file}: {err}"))?;

        let root_ca_file = env::var("CERT_ENROLMENT_ROOT_CA_FILE")
            .or_else(|_| env::var("SSL_CERT_FILE"))
            .map_err(|_| "CERT_ENROLMENT_ROOT_CA_FILE or SSL_CERT_FILE must be set")?;

        let api_key = secret_file("CERT_ENROLMENT_RA_API_KEY_FILE")?;
        if api_key.len() < 32 {
            return Err("the RA API key must be at least 32 characters".to_string());
        }

        Ok(Config {
            listen: listen_address("0.0.0.0:8080"),
            ldap_url,
            ldap_people_dn: required("CERT_ENROLMENT_LDAP_PEOPLE_DN")?,
            ldap_bind_dn: required("CERT_ENROLMENT_LDAP_BIND_DN")?,
            ldap_bind_password: secret_file("CERT_ENROLMENT_LDAP_BIND_PASSWORD_FILE")?,
            ldap_devices_dn: required("CERT_ENROLMENT_LDAP_DEVICES_DN")?,
            device_domain: required("CERT_ENROLMENT_DEVICE_DOMAIN")?.to_ascii_lowercase(),
            device_zones: parse_zones(&required("CERT_ENROLMENT_DEVICE_ZONES")?)?,
            ca_url,
            provisioner_name: required("CERT_ENROLMENT_PROVISIONER")?,
            provisioner_key,
            root_ca_pem: certificate_file(&root_ca_file)?,
            api_key,
        })
    }
}
