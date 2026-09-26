//! The registration authority (RA) role.
//!
//! The RA owns device records and every device certificate. It is the only
//! part that holds the LDAP service account and the step-ca provisioner key.
//!
//! * The portal calls `/api/...` with a bearer key, naming the signed-in user
//!   in `X-Actor` for auditing.
//! * Devices call `/v1/enrol` with a single-use enrolment code, and
//!   `/v1/renew` presenting their current certificate. A reverse proxy
//!   terminates TLS, verifies client certificates against the Root CA, and
//!   passes the result in `X-Client-Verify` and `X-Client-Cert`.
//!
//! The RA obtains every certificate from step-ca itself and records its
//! serial, so deleting a device revokes all of its certificates in step-ca.

mod certs;
mod codes;
mod config;
mod devices;
mod stepca;
mod token;

use std::process::ExitCode;

use serde_json::{json, Value};
use tiny_http::{Method, Request, Server};

use crate::shared::device::{device_id, label_from_id, valid_description, valid_label, Platform};
use crate::shared::http::{self, json_error, Reply};
use crate::shared::random::tokens_match;
use crate::shared::time;
use crate::shared::user::valid_username;
use codes::Codes;
use config::Config;
use devices::{Change, Created, Record};
use stepca::{CaError, StepCa};
use token::Provisioner;

struct Ra {
    config: Config,
    provisioner: Provisioner,
    ca: StepCa,
    codes: Codes,
}

pub fn run() -> ExitCode {
    let mut ra = match start() {
        Ok(ra) => ra,
        Err(err) => {
            eprintln!("cert-enrolment ra: {err}");
            return ExitCode::FAILURE;
        }
    };

    let server = match Server::http(&ra.config.listen) {
        Ok(server) => server,
        Err(err) => {
            eprintln!("cert-enrolment ra: cannot listen on {}: {err}", ra.config.listen);
            return ExitCode::FAILURE;
        }
    };
    eprintln!("cert-enrolment ra: listening on {}", ra.config.listen);

    for mut request in server.incoming_requests() {
        let response = route(&mut ra, &mut request);
        if let Err(err) = request.respond(response) {
            eprintln!("cert-enrolment ra: failed to send response: {err}");
        }
    }
    ExitCode::SUCCESS
}

/// Everything is checked at start-up, so a bad key or setting fails the
/// deployment rather than the first enrolment.
fn start() -> Result<Ra, String> {
    let config = Config::from_env()?;
    let provisioner = Provisioner::new(&config.ca_url, &config.provisioner_name, &config.provisioner_key)?;
    let ca = StepCa::new(&config.ca_url, &config.root_ca_pem)?;
    Ok(Ra { config, provisioner, ca, codes: Codes::default() })
}

fn route(ra: &mut Ra, request: &mut Request) -> Reply {
    let path = request.url().split('?').next().unwrap_or("/").to_string();
    let method = request.method().clone();

    match (&method, path.as_str()) {
        (Method::Get, "/healthz") => http::text(200, "ok\n"),
        (Method::Post, "/v1/enrol") => enrol(ra, request),
        (Method::Post, "/v1/renew") => renew(ra, request),
        (_, api) if api.starts_with("/api/") => {
            let authorised = http::header(request, "Authorization")
                .and_then(|value| value.strip_prefix("Bearer "))
                .is_some_and(|key| tokens_match(key, &ra.config.api_key));
            if !authorised {
                return json_error(401, "The RA API key is missing or wrong.");
            }
            let actor = http::header(request, "X-Actor").filter(|actor| valid_username(actor)).map(str::to_string);
            let Some(actor) = actor else {
                return json_error(400, "X-Actor must name the signed-in user.");
            };
            let segments: Vec<String> = api.trim_start_matches("/api/").split('/').map(str::to_string).collect();
            let segments: Vec<&str> = segments.iter().map(String::as_str).collect();
            api_route(ra, request, &method, &segments, &actor)
        }
        _ => json_error(404, "Not found."),
    }
}

fn api_route(ra: &mut Ra, request: &mut Request, method: &Method, segments: &[&str], actor: &str) -> Reply {
    match (method, segments) {
        (Method::Get, ["devices"]) => match devices::list(&ra.config) {
            Ok(list) => http::json(200, &json!({ "devices": list.iter().map(|d| d.to_json()).collect::<Vec<_>>() })),
            Err(err) => unavailable(&err),
        },
        (Method::Post, ["devices"]) => create_device(ra, request, actor),
        (Method::Get, ["devices", label]) => with_record(ra, label, |_, record| http::json(200, &record.device.to_json())),
        (Method::Delete, ["devices", label]) => delete_device(ra, label, actor),
        (Method::Post, ["devices", label, "disable"]) => set_disabled(ra, label, true, actor),
        (Method::Post, ["devices", label, "enable"]) => set_disabled(ra, label, false, actor),
        (Method::Post, ["devices", label, "enrolment-code"]) => enrolment_code(ra, label, actor),
        _ => json_error(404, "Not found."),
    }
}

fn unavailable(err: &str) -> Reply {
    eprintln!("cert-enrolment ra: {err}");
    json_error(503, "The directory or certificate authority is unavailable. Try again shortly.")
}

fn now() -> String {
    time::generalized_time(time::now_unix()).unwrap_or_default()
}

/// Looks up a device named by a validated label, answering 404 if it is not
/// registered.
fn with_record(ra: &mut Ra, label: &str, then: impl FnOnce(&mut Ra, Record) -> Reply) -> Reply {
    if !valid_label(label) {
        return json_error(400, "That is not a device name.");
    }
    match devices::get(&ra.config, label) {
        Ok(Some(record)) => then(ra, record),
        Ok(None) => json_error(404, &format!("{} is not registered.", device_id(&ra.config.device_domain, label))),
        Err(err) => unavailable(&err),
    }
}

// Portal API ------------------------------------------------------------------

fn create_device(ra: &mut Ra, request: &mut Request, actor: &str) -> Reply {
    let Ok(body) = http::read_json(request) else {
        return json_error(400, "Expected a JSON body.");
    };
    let field = |name: &str| body.get(name).and_then(Value::as_str).unwrap_or("").trim().to_string();
    let (label, description, zone) = (field("label").to_ascii_lowercase(), field("description"), field("zone"));
    let platform = Platform::from_id(&field("platform"));

    let problem = if !valid_label(&label) {
        Some("Device names are 1 to 63 lowercase letters, digits and hyphens, and cannot start or end with a hyphen.")
    } else if !valid_description(&description) {
        Some("Descriptions are up to 64 characters, on one line.")
    } else if !ra.config.device_zones.contains(&zone) {
        Some("Choose one of the listed network zones.")
    } else if platform.is_none() {
        Some("Choose one of the listed device types.")
    } else {
        None
    };
    let (None, Some(platform)) = (problem, platform) else {
        return json_error(400, problem.unwrap_or("Invalid device."));
    };

    match devices::create(&ra.config, &label, &description, platform, &zone, actor) {
        Ok(Created::Created(device)) => {
            eprintln!("cert-enrolment ra: {actor} registered {} ({}, zone {zone})", device.id, platform.id());
            http::json(201, &device.to_json())
        }
        Ok(Created::AlreadyExists) => {
            json_error(409, &format!("{} is already registered.", device_id(&ra.config.device_domain, &label)))
        }
        Err(err) => unavailable(&err),
    }
}

fn set_disabled(ra: &mut Ra, label: &str, disabled: bool, actor: &str) -> Reply {
    with_record(ra, label, |ra, record| match devices::set_disabled(&ra.config, label, disabled) {
        Ok(Change::Done) => {
            eprintln!("cert-enrolment ra: {actor} {} {}", if disabled { "disabled" } else { "enabled" }, record.device.id);
            http::no_content()
        }
        Ok(Change::NotFound) => json_error(404, &format!("{} is not registered.", record.device.id)),
        Err(err) => unavailable(&err),
    })
}

/// Deletes a device and revokes its certificates. The device is disabled
/// first, so that if revocation fails part-way it is at least refused on
/// the network and cannot renew; deleting again resumes.
fn delete_device(ra: &mut Ra, label: &str, actor: &str) -> Reply {
    with_record(ra, label, |ra, record| {
        let id = record.device.id.clone();
        if let Err(err) = devices::set_disabled(&ra.config, label, true) {
            return unavailable(&err);
        }

        let now = now();
        for certificate in record.certificates.iter().filter(|c| c.not_after > now) {
            let Some(serial) = certs::serial_decimal(&certificate.serial_hex) else {
                eprintln!("cert-enrolment ra: skipping unreadable serial {} of {id}", certificate.serial_hex);
                continue;
            };
            let result = ra
                .provisioner
                .revoke_token(&serial)
                .map_err(CaError::Unavailable)
                .and_then(|token| ra.ca.revoke(&serial, &token, &format!("device {id} deleted by {actor}")));
            if let Err(err) = result {
                eprintln!("cert-enrolment ra: revoking serial {serial} of {id} failed: {err}");
                return json_error(
                    502,
                    &format!("{id} has been disabled, but its certificates could not all be revoked. Try deleting it again."),
                );
            }
            eprintln!("cert-enrolment ra: revoked serial {serial} of {id}");
        }

        match devices::delete(&ra.config, label) {
            Ok(_) => {
                eprintln!("cert-enrolment ra: {actor} deleted {id}");
                http::no_content()
            }
            Err(err) => unavailable(&err),
        }
    })
}

fn enrolment_code(ra: &mut Ra, label: &str, actor: &str) -> Reply {
    with_record(ra, label, |ra, record| {
        if record.device.disabled {
            return json_error(409, "This device is disabled. Enable it before enrolling it.");
        }
        match ra.codes.issue(label) {
            Ok(code) => {
                eprintln!("cert-enrolment ra: {actor} requested an enrolment code for {}", record.device.id);
                http::json(200, &json!({ "code": code, "expiresInSeconds": codes::LIFETIME.as_secs() }))
            }
            Err(err) => unavailable(&err),
        }
    })
}

// Device endpoints ------------------------------------------------------------

/// First certificate for a device, authorised by an enrolment code.
fn enrol(ra: &mut Ra, request: &mut Request) -> Reply {
    let Ok(body) = http::read_json(request) else {
        return json_error(400, "Expected a JSON body with code and csr.");
    };
    let text = |name: &str| body.get(name).and_then(Value::as_str).unwrap_or("").to_string();
    let (code, csr) = (text("code"), text("csr"));

    let Some(label) = ra.codes.device(&code) else {
        return json_error(
            401,
            "The enrolment code is not valid: it may have expired or already been used. Download a new script from the Enrol page.",
        );
    };
    let record = match devices::get(&ra.config, &label) {
        Ok(Some(record)) => record,
        Ok(None) => return json_error(404, "This device is no longer registered."),
        Err(err) => return unavailable(&err),
    };
    if record.device.disabled {
        return json_error(403, "This device is disabled.");
    }

    match issue(ra, &record, &csr) {
        Ok(reply) => {
            ra.codes.spend(&code);
            eprintln!("cert-enrolment ra: enrolled {}", record.device.id);
            reply
        }
        Err(reply) => reply,
    }
}

/// A new certificate for a device, authorised by its current one. Only the
/// newest certificate recorded for the device may renew, so a copy of an
/// older one cannot, and neither can certificates from before a device was
/// deleted and registered again.
fn renew(ra: &mut Ra, request: &mut Request) -> Reply {
    if http::header(request, "X-Client-Verify") != Some("SUCCESS") {
        return json_error(401, "Renewal needs the device's current certificate.");
    }
    let presented = http::header(request, "X-Client-Cert")
        .and_then(|escaped| http::percent_decode(escaped).ok())
        .and_then(|pem| certs::parse_pem(&pem).ok());
    let Some(presented) = presented else {
        return json_error(401, "The client certificate could not be read.");
    };

    let Some(label) = label_from_id(&ra.config.device_domain, &presented.common_name).map(str::to_string) else {
        return json_error(403, "This is not a device certificate.");
    };
    let record = match devices::get(&ra.config, &label) {
        Ok(Some(record)) => record,
        Ok(None) => return json_error(403, "This device is not registered."),
        Err(err) => return unavailable(&err),
    };
    if record.device.disabled {
        return json_error(403, "This device is disabled.");
    }
    if presented.not_after <= now() {
        return json_error(403, "This certificate has expired; enrol the device again.");
    }
    if record.newest_certificate().map(|c| c.serial_hex.as_str()) != Some(presented.serial_hex.as_str()) {
        eprintln!(
            "cert-enrolment ra: refused renewal of {} with serial {}, which is not its newest certificate",
            record.device.id, presented.serial_hex
        );
        return json_error(403, "Only the device's newest certificate can renew; enrol the device again.");
    }

    let Ok(body) = http::read_json(request) else {
        return json_error(400, "Expected a JSON body with csr.");
    };
    let csr = body.get("csr").and_then(Value::as_str).unwrap_or("").to_string();
    match issue(ra, &record, &csr) {
        Ok(reply) => {
            eprintln!("cert-enrolment ra: renewed {}", record.device.id);
            reply
        }
        Err(reply) => reply,
    }
}

/// Obtains a certificate for the device from step-ca and records it. step-ca
/// only signs the request if it is for exactly this device's name.
fn issue(ra: &Ra, record: &Record, csr: &str) -> Result<Reply, Reply> {
    if !csr.starts_with("-----BEGIN CERTIFICATE REQUEST-----") {
        return Err(json_error(400, "Expected a PEM certificate request."));
    }
    let token = ra.provisioner.sign_token(&record.device.id).map_err(|err| unavailable(&err))?;
    let issued = ra.ca.sign(csr, &token).map_err(|err| match err {
        CaError::Refused { status, message } => {
            eprintln!("cert-enrolment ra: step-ca refused {} (HTTP {status}): {message}", record.device.id);
            json_error(422, &format!("The certificate authority refused the request: {message}"))
        }
        CaError::Unavailable(reason) => unavailable(&reason),
    })?;

    let info = certs::parse_pem(&issued.certificate).map_err(|err| unavailable(&err))?;
    if info.common_name != record.device.id {
        return Err(unavailable(&format!("step-ca issued {} for {}", info.common_name, record.device.id)));
    }
    devices::record_certificate(&ra.config, record, &info, &now()).map_err(|err| unavailable(&err))?;

    Ok(http::json(201, &json!({ "crt": issued.certificate, "ca": issued.intermediate })))
}
