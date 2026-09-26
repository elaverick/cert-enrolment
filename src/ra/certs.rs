//! What the RA needs to know about a certificate: whose it is, its serial and
//! when it expires.

use x509_parser::num_bigint::BigUint;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::shared::time::generalized_time;

pub struct CertificateInfo {
    pub common_name: String,
    /// Serial as lowercase hex bytes, as FreeRADIUS reports it
    /// (`TLS-Client-Cert-Serial`).
    pub serial_hex: String,
    /// Expiry as an LDAP GeneralizedTime, `YYYYMMDDHHMMSSZ`.
    pub not_after: String,
}

pub fn parse_pem(pem: &str) -> Result<CertificateInfo, String> {
    let (_, block) = parse_x509_pem(pem.as_bytes()).map_err(|err| format!("not a PEM certificate: {err}"))?;
    let (_, certificate) =
        X509Certificate::from_der(&block.contents).map_err(|err| format!("not an X.509 certificate: {err}"))?;

    let common_name = certificate
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .ok_or("certificate has no Common Name")?
        .to_string();

    Ok(CertificateInfo {
        common_name,
        serial_hex: serial_hex(&certificate.tbs_certificate.serial),
        not_after: generalized_time(certificate.validity().not_after.timestamp())?,
    })
}

/// Lowercase hex with an even number of digits: the serial's bytes.
fn serial_hex(serial: &BigUint) -> String {
    let hex = serial.to_str_radix(16);
    if hex.len() % 2 == 1 {
        format!("0{hex}")
    } else {
        hex
    }
}

/// step-ca identifies certificates by their serial in decimal.
pub fn serial_decimal(serial_hex: &str) -> Option<String> {
    BigUint::parse_bytes(serial_hex.as_bytes(), 16).map(|serial| serial.to_str_radix(10))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_formats() {
        let serial = BigUint::parse_bytes(b"0abc", 16).unwrap();
        assert_eq!(serial_hex(&serial), "0abc");
        assert_eq!(serial_decimal("0abc").unwrap(), "2748");
        assert_eq!(serial_decimal("ff").unwrap(), "255");
        assert!(serial_decimal("xyz").is_none());
    }

    #[test]
    fn reads_a_certificate() {
        // A throwaway self-signed certificate: CN=tv.device.example.home.arpa,
        // serial 0x1f3c, valid for ten years from 2026-09-26.
        let info = parse_pem(TEST_CERTIFICATE).unwrap();
        assert_eq!(info.common_name, "tv.device.example.home.arpa");
        assert_eq!(info.serial_hex, "1f3c");
        assert_eq!(info.not_after, "20360923144420Z");
    }

    const TEST_CERTIFICATE: &str = include_str!("test-certificate.pem");
}
