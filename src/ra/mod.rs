//! The registration authority (RA) role. Not implemented yet.

use std::process::ExitCode;

pub fn run() -> ExitCode {
    eprintln!("cert-enrolment: the ra role is not implemented yet");
    ExitCode::FAILURE
}
