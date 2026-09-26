//! What the RA needs to know about a certificate: whose it is, its serial and
//! when it expires.

use x509_parser::num_bigint::BigUint;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::{FromDer, X509Certificate};

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

/// Seconds since the Unix epoch as `YYYYMMDDHHMMSSZ`.
pub fn generalized_time(unix: i64) -> Result<String, String> {
    if unix < 0 {
        return Err("time before 1970".to_string());
    }
    let days = unix / 86_400;
    let seconds = unix % 86_400;

    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);

    Ok(format!(
        "{year:04}{month:02}{day:02}{:02}{:02}{:02}Z",
        seconds / 3_600,
        seconds % 3_600 / 60,
        seconds % 60
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_generalized_time() {
        assert_eq!(generalized_time(0).unwrap(), "19700101000000Z");
        assert_eq!(generalized_time(951_782_400).unwrap(), "20000229000000Z");
        assert_eq!(generalized_time(1_793_024_071).unwrap(), "20261026141431Z");
        assert!(generalized_time(-1).is_err());
    }

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
