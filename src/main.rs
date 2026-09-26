//! cert-enrolment - device certificate enrolment for an 802.1X (EAP-TLS) Wi-Fi network.
//!
//! One binary with two roles, chosen by `CERT_ENROLMENT_ROLE`:
//!
//! * `portal` - the web pages people use to enrol and manage devices.
//! * `ra` - the registration authority: owns device records, obtains
//!   certificates from step-ca and revokes them.

mod portal;
mod ra;
mod shared;

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    // Defaults to the portal so that deployments made before the RA existed
    // keep working until they set the role explicitly.
    let role = env::var("CERT_ENROLMENT_ROLE").unwrap_or_else(|_| "portal".to_string());

    match role.as_str() {
        "portal" => portal::run(),
        "ra" => ra::run(),
        other => {
            eprintln!("cert-enrolment: CERT_ENROLMENT_ROLE must be portal or ra, not {other:?}");
            ExitCode::FAILURE
        }
    }
}
