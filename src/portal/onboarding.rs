//! The onboarding site: plain HTTP, for devices that do not trust the Root
//! CA yet. It serves only the Root CA, in the forms devices need, and a page
//! that sends people on to the portal over HTTPS. It has no sign-in,
//! sessions or cookies, and shares nothing with the portal but the Root CA
//! and the stylesheet.

use sha2::{Digest, Sha256};
use tiny_http::{Method, Request, Server};
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::{FromDer, X509Certificate};

use super::{assets, pages};
use crate::shared::http::{self, escape, Reply};

pub struct Onboarding {
    /// The portal over HTTPS, where the page sends people.
    public_url: String,
    pem: String,
    der: Vec<u8>,
    /// SHA-256 of the certificate as spaced hex pairs, as iOS shows it.
    fingerprint: String,
    common_name: String,
    mobileconfig: String,
}

impl Onboarding {
    pub fn new(root_ca_pem: &str, public_url: &str) -> Result<Onboarding, String> {
        let (_, pem) = parse_x509_pem(root_ca_pem.as_bytes()).map_err(|err| format!("cannot read the Root CA: {err}"))?;
        let der = pem.contents;
        let (_, certificate) =
            X509Certificate::from_der(&der).map_err(|err| format!("cannot read the Root CA: {err}"))?;
        let common_name = certificate
            .subject()
            .iter_common_name()
            .next()
            .and_then(|name| name.as_str().ok())
            .unwrap_or("Root CA")
            .to_string();

        let digest = Sha256::digest(&der);
        let fingerprint = digest.iter().map(|byte| format!("{byte:02X}")).collect::<Vec<_>>().join(" ");
        let mobileconfig = mobileconfig(&der, &digest, &common_name, public_url);

        Ok(Onboarding {
            public_url: public_url.to_string(),
            pem: format!("{root_ca_pem}\n"),
            der,
            fingerprint,
            common_name,
            mobileconfig,
        })
    }
}

pub fn serve(server: Server, onboarding: Onboarding) {
    for request in server.incoming_requests() {
        let response = route(&onboarding, &request);
        if let Err(err) = request.respond(response) {
            eprintln!("cert-enrolment onboarding: failed to send response: {err}");
        }
    }
}

fn route(onboarding: &Onboarding, request: &Request) -> Reply {
    if !matches!(request.method(), Method::Get | Method::Head) {
        return http::text(405, "method not allowed\n");
    }

    let path = request.url().split('?').next().unwrap_or("/");
    if let Some(asset) = assets::get(path) {
        return asset;
    }

    match path {
        "/healthz" => http::text(200, "ok\n"),
        "/" => http::html(
            200,
            pages::onboarding(&onboarding.common_name, &onboarding.fingerprint, &onboarding.public_url),
        ),
        "/root-ca.cer" => http::download("root-ca.cer", "application/pkix-cert", onboarding.der.clone()),
        "/root-ca.crt" => http::download("root-ca.crt", "application/x-pem-file", onboarding.pem.clone()),
        "/root-ca.mobileconfig" => http::download(
            "root-ca.mobileconfig",
            "application/x-apple-aspen-config",
            onboarding.mobileconfig.clone(),
        ),
        // Captive portals add their own paths and parameters; everything
        // else leads to the page.
        _ => http::redirect("/"),
    }
}

/// An unsigned iOS configuration profile holding only the Root CA. Its
/// identifiers derive from the certificate, so downloading it again gives
/// the same profile, and a new Root CA a different one.
fn mobileconfig(der: &[u8], digest: &[u8], common_name: &str, public_url: &str) -> String {
    let host = public_url.trim_start_matches("https://").split(':').next().unwrap_or_default();
    let identifier = host.split('.').rev().collect::<Vec<_>>().join(".");
    let short = digest[..8].iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let certificate = base64_lines(der);

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>root-ca.cer</string>
			<key>PayloadContent</key>
			<data>
{certificate}
			</data>
			<key>PayloadDisplayName</key>
			<string>{name}</string>
			<key>PayloadIdentifier</key>
			<string>{identifier}.root-ca.{short}.certificate</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>{certificate_uuid}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>Trusts the certificate authority of this network, so that this device can enrol.</string>
	<key>PayloadDisplayName</key>
	<string>{name}</string>
	<key>PayloadIdentifier</key>
	<string>{identifier}.root-ca.{short}</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>{profile_uuid}</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
"#,
        name = escape(common_name),
        identifier = escape(&identifier),
        certificate_uuid = uuid(&digest[..16]),
        profile_uuid = uuid(&digest[16..32]),
    )
}

fn base64_lines(der: &[u8]) -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    encoded
        .as_bytes()
        .chunks(64)
        .map(|line| format!("\t\t\t{}", String::from_utf8_lossy(line)))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A version 4 style UUID from 16 bytes of a digest.
fn uuid(bytes: &[u8]) -> String {
    let mut bytes: [u8; 16] = bytes.try_into().expect("16 bytes");
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02X}")).collect();
    format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32])
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_CA: &str = include_str!("../ra/test-certificate.pem");

    #[test]
    fn describes_the_root_ca() {
        let onboarding = Onboarding::new(ROOT_CA.trim(), "https://join.example.home.arpa").unwrap();
        assert_eq!(onboarding.common_name, "tv.device.example.home.arpa");
        assert_eq!(onboarding.fingerprint.len(), 32 * 3 - 1);
        assert_eq!(
            onboarding.fingerprint.replace(' ', "").to_lowercase(),
            Sha256::digest(&onboarding.der).iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        assert!(onboarding.pem.starts_with("-----BEGIN CERTIFICATE-----") && onboarding.pem.ends_with("-----\n"));
    }

    #[test]
    fn profile_holds_the_root_ca() {
        let onboarding = Onboarding::new(ROOT_CA.trim(), "https://join.example.home.arpa:8443").unwrap();
        let profile = &onboarding.mobileconfig;
        assert!(profile.contains("<string>com.apple.security.root</string>"));
        assert!(profile.contains("<string>arpa.home.example.join.root-ca."));
        let body: String = ROOT_CA.lines().filter(|line| !line.starts_with("-----")).collect();
        let data: String = profile
            .split("<data>")
            .nth(1)
            .and_then(|rest| rest.split("</data>").next())
            .unwrap()
            .split_whitespace()
            .collect();
        assert_eq!(data, body);
    }

    #[test]
    fn uuids_are_version_4() {
        let uuid = uuid(&[0xff; 16]);
        assert_eq!(uuid, "FFFFFFFF-FFFF-4FFF-BFFF-FFFFFFFFFFFF");
    }
}
