//! The portal role: the web pages for signing in, enrolling devices and
//! managing them.
//!
//! Plain HTTP only: a reverse proxy terminates TLS for the portal host name.
//! Optionally, a second listener serves the same pages over plain HTTP, as
//! the onboarding network's captive portal. Each listener has its own
//! sessions and cookies, so a session never crosses between them.

mod assets;
mod config;
mod directory;
mod enrolment;
mod pages;
mod ra_client;
mod session;

use std::process::ExitCode;
use std::sync::mpsc::{self, Sender};
use std::thread;

use tiny_http::{Method, Request, Server};

use crate::shared::device::{device_id, label_from_id, valid_description, valid_label, Platform};
use crate::shared::http::{self, Cookies, Reply, HTTPS_COOKIES, ONBOARDING_COOKIES};
use crate::shared::random::{random_token, tokens_match};
use crate::shared::time;
use config::Config;
use directory::SignIn;
use ra_client::{RaClient, RaError};
use session::Sessions;

pub fn run() -> ExitCode {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("cert-enrolment: {err}");
            return ExitCode::FAILURE;
        }
    };

    let ra = RaClient::new(&config.ra_url, &config.ra_api_key);

    // Requests from every listener are handled one at a time on this thread,
    // tagged with the listener's index into `sessions`.
    let (sender, requests) = mpsc::channel();
    let mut sessions = vec![Sessions::new(config.session_idle, HTTPS_COOKIES)];
    if let Err(err) = listen(&config.listen, 0, sender.clone()) {
        eprintln!("cert-enrolment: {err}");
        return ExitCode::FAILURE;
    }
    if let Some(address) = &config.onboarding_listen {
        sessions.push(Sessions::new(config.session_idle, ONBOARDING_COOKIES));
        if let Err(err) = listen(address, 1, sender.clone()) {
            eprintln!("cert-enrolment: {err} (onboarding)");
            return ExitCode::FAILURE;
        }
    }
    drop(sender);

    for (mut request, listener) in requests {
        let response = route(&config, &ra, &mut sessions[listener], &mut request);

        if let Err(err) = request.respond(response) {
            eprintln!("cert-enrolment: failed to send response: {err}");
        }
    }

    ExitCode::SUCCESS
}

/// Accepts requests on `address` and passes them on, tagged with `listener`.
fn listen(address: &str, listener: usize, sender: Sender<(Request, usize)>) -> Result<(), String> {
    let server = Server::http(address).map_err(|err| format!("cannot listen on {address}: {err}"))?;
    eprintln!("cert-enrolment: listening on {address}");
    thread::spawn(move || {
        for request in server.incoming_requests() {
            if sender.send((request, listener)).is_err() {
                break;
            }
        }
    });
    Ok(())
}

fn route(config: &Config, ra: &RaClient, sessions: &mut Sessions, request: &mut Request) -> Reply {
    let path = request.url().split('?').next().unwrap_or("/").to_string();

    if *request.method() == Method::Get {
        if let Some(asset) = assets::get(&path) {
            return asset;
        }
    }

    match (request.method(), path.as_str()) {
        (Method::Get, "/healthz") => http::text(200, "ok\n"),
        (Method::Get, "/") => match signed_in(sessions, request) {
            Some(_) => http::redirect("/enrol"),
            None => http::redirect("/login"),
        },
        (Method::Get, "/enrol") => enrol_form(config, sessions, request),
        (Method::Post, "/enrol") => register_device(config, ra, sessions, request),
        (Method::Get, "/enrol/device") => enrolled(ra, sessions, request),
        (Method::Post, "/enrol/download") => download_script(config, ra, sessions, request),
        (Method::Get, "/devices") => device_list(config, ra, sessions, request),
        (Method::Post, "/devices/disable") => device_action(config, ra, sessions, request, Action::Disable),
        (Method::Post, "/devices/enable") => device_action(config, ra, sessions, request, Action::Enable),
        (Method::Post, "/devices/delete") => device_action(config, ra, sessions, request, Action::Delete),
        (Method::Get, "/login") => sign_in_form(sessions, request),
        (Method::Post, "/login") => sign_in(config, sessions, request),
        (Method::Post, "/logout") => sign_out(sessions, request),
        // Captive portals add their own paths and parameters.
        (Method::Get, _) => http::redirect("/"),
        _ => http::text(404, "not found\n"),
    }
}

/// The signed-in user and their CSRF token, copied out of the session.
struct SignedIn {
    username: String,
    csrf_token: String,
}

fn signed_in(sessions: &mut Sessions, request: &Request) -> Option<SignedIn> {
    let session = sessions.get(http::cookie(request, sessions.cookies.session)?)?;
    Some(SignedIn { username: session.username.clone(), csrf_token: session.csrf_token.clone() })
}

/// Reads a POSTed form and checks it carries the session's CSRF token.
fn session_form(request: &mut Request, user: &SignedIn) -> Option<Vec<(String, String)>> {
    let form = http::read_form(request).ok()?;
    tokens_match(&user.csrf_token, http::form_value(&form, "csrf")).then_some(form)
}

fn unavailable(err: &str) -> Reply {
    eprintln!("cert-enrolment: {err}");
    http::html(503, pages::unavailable())
}

fn ra_unavailable(err: RaError) -> Reply {
    match err {
        RaError::Unavailable(reason) => unavailable(&reason),
        RaError::Rejected { status, message } => unavailable(&format!("the RA refused a request (HTTP {status}): {message}")),
    }
}

// Enrolment

/// Values the registration form is refilled with after an error.
#[derive(Default)]
struct DeviceForm<'a> {
    label: &'a str,
    description: &'a str,
    platform: Option<Platform>,
    zone: &'a str,
}

fn enrol_form(config: &Config, sessions: &mut Sessions, request: &Request) -> Reply {
    let Some(user) = signed_in(sessions, request) else {
        return http::redirect("/login");
    };
    enrol_page(config, &user, 200, &DeviceForm::default(), None)
}

fn enrol_page(config: &Config, user: &SignedIn, status: u16, form: &DeviceForm, error: Option<&str>) -> Reply {
    http::html(
        status,
        pages::enrol(&pages::EnrolForm {
            csrf_token: &user.csrf_token,
            device_domain: &config.device_domain,
            zones: &config.device_zones,
            label: form.label,
            description: form.description,
            platform: form.platform,
            zone: form.zone,
            error,
        }),
    )
}

fn register_device(config: &Config, ra: &RaClient, sessions: &mut Sessions, request: &mut Request) -> Reply {
    let Some(user) = signed_in(sessions, request) else {
        return http::redirect("/login");
    };
    let Some(form) = session_form(request, &user) else {
        return http::text(400, "bad request\n");
    };

    let label = http::form_value(&form, "label").trim().to_ascii_lowercase();
    let description = http::form_value(&form, "description").trim();
    let platform = Platform::from_id(http::form_value(&form, "platform"));
    let zone = http::form_value(&form, "zone");
    let refill = DeviceForm { label: &label, description, platform, zone };

    let problem = if !valid_label(&label) {
        Some("Device names are 1 to 63 lowercase letters, digits and hyphens, and cannot start or end with a hyphen.")
    } else if !valid_description(description) {
        Some("Descriptions are up to 64 characters, on one line.")
    } else if !config.device_zones.iter().any(|allowed| allowed == zone) {
        Some("Choose one of the listed network zones.")
    } else if platform.is_none() {
        Some("Choose one of the listed device types.")
    } else {
        None
    };
    let (None, Some(platform)) = (problem, platform) else {
        return enrol_page(config, &user, 400, &refill, problem);
    };

    match ra.create(&user.username, &label, description, platform.id(), zone) {
        Ok(device) => {
            eprintln!("cert-enrolment: {} registered {} ({}, zone {zone})", user.username, device.id, platform.id());
            http::redirect(&format!("/enrol/device?device={label}"))
        }
        Err(RaError::Rejected { status: status @ (400 | 409), message }) => {
            enrol_page(config, &user, status, &refill, Some(&message))
        }
        Err(err) => ra_unavailable(err),
    }
}

/// Step 3 for a registered device, named by the validated `device` query
/// parameter.
fn enrolled(ra: &RaClient, sessions: &mut Sessions, request: &Request) -> Reply {
    let Some(user) = signed_in(sessions, request) else {
        return http::redirect("/login");
    };
    let Some(label) = http::query_value(request, "device").filter(|label| valid_label(label)) else {
        return http::redirect("/enrol");
    };

    match ra.get(&user.username, label) {
        Ok(Some(device)) => http::html(200, pages::enrolled(&device, &user.csrf_token, None)),
        Ok(None) => http::redirect("/enrol"),
        Err(err) => ra_unavailable(err),
    }
}

/// Returns the enrolment script for a registered, enabled device, with a
/// fresh single-use enrolment code from the RA written in.
fn download_script(config: &Config, ra: &RaClient, sessions: &mut Sessions, request: &mut Request) -> Reply {
    let Some(user) = signed_in(sessions, request) else {
        return http::redirect("/login");
    };
    let Some(form) = session_form(request, &user) else {
        return http::text(400, "bad request\n");
    };
    let label = http::form_value(&form, "device");
    if !valid_label(label) {
        return http::text(400, "bad request\n");
    }

    let device = match ra.get(&user.username, label) {
        Ok(Some(device)) => device,
        Ok(None) => return http::redirect("/enrol"),
        Err(err) => return ra_unavailable(err),
    };
    if device.disabled {
        let error = "This device is disabled. Enable it under Devices before enrolling it.";
        return http::html(409, pages::enrolled(&device, &user.csrf_token, Some(error)));
    }

    let Some(platform) = Platform::from_id(&device.platform) else {
        return http::text(400, "bad request\n");
    };
    let code = match ra.enrolment_code(&user.username, label) {
        Ok(code) => code,
        Err(RaError::Rejected { status: 409, message }) => {
            return http::html(409, pages::enrolled(&device, &user.csrf_token, Some(&message)));
        }
        Err(err) => return ra_unavailable(err),
    };
    let Some(script) = enrolment::script(config, platform, label, &device.id, &code) else {
        return http::text(400, "bad request\n");
    };

    eprintln!("cert-enrolment: {} downloaded the enrolment script for {}", user.username, device.id);
    http::download(&script.file_name, script.content_type, script.body)
}

// Device management

/// Changes made from the device list, reported back to it after a redirect.
#[derive(Clone, Copy)]
enum Action {
    Disable,
    Enable,
    Delete,
}

impl Action {
    const ALL: [Action; 3] = [Action::Disable, Action::Enable, Action::Delete];

    fn done(self) -> &'static str {
        match self {
            Action::Disable => "disabled",
            Action::Enable => "enabled",
            Action::Delete => "deleted",
        }
    }

    fn past_tense(self) -> &'static str {
        match self {
            Action::Disable => "Disabled",
            Action::Enable => "Enabled",
            Action::Delete => "Deleted",
        }
    }
}

fn device_list(config: &Config, ra: &RaClient, sessions: &mut Sessions, request: &Request) -> Reply {
    let Some(user) = signed_in(sessions, request) else {
        return http::redirect("/login");
    };

    // Set by the redirect after a change. Both values are validated, so
    // nothing from the URL reaches the page unchecked.
    let notice = http::query_value(request, "device")
        .filter(|label| valid_label(label))
        .zip(http::query_value(request, "done").and_then(|done| Action::ALL.into_iter().find(|a| a.done() == done)))
        .map(|(label, action)| format!("{} {}.", action.past_tense(), device_id(&config.device_domain, label)));

    device_list_page(ra, &user, 200, notice.as_deref(), None)
}

fn device_list_page(ra: &RaClient, user: &SignedIn, status: u16, notice: Option<&str>, error: Option<&str>) -> Reply {
    match ra.list(&user.username) {
        Ok(device_list) => http::html(status, pages::devices(&device_list, &user.csrf_token, time::now_unix(), notice, error)),
        Err(err) => ra_unavailable(err),
    }
}

/// Disables, enables or deletes the device named by the form's `id`.
/// Deleting first shows a confirmation page, which posts back with
/// `confirm=yes`.
fn device_action(config: &Config, ra: &RaClient, sessions: &mut Sessions, request: &mut Request, action: Action) -> Reply {
    let Some(user) = signed_in(sessions, request) else {
        return http::redirect("/login");
    };
    let Some(form) = session_form(request, &user) else {
        return http::text(400, "bad request\n");
    };

    let id = http::form_value(&form, "id");
    let Some(label) = label_from_id(&config.device_domain, id) else {
        return device_list_page(ra, &user, 400, None, Some("That is not a device name."));
    };

    let result = match action {
        Action::Delete if http::form_value(&form, "confirm") != "yes" => {
            return http::html(200, pages::confirm_delete(id, &user.csrf_token));
        }
        Action::Delete => ra.delete(&user.username, label),
        Action::Disable => ra.set_disabled(&user.username, label, true),
        Action::Enable => ra.set_disabled(&user.username, label, false),
    };

    match result {
        Ok(()) => {
            eprintln!("cert-enrolment: {} {} {id}", user.username, action.done());
            http::redirect(&format!("/devices?done={}&device={label}", action.done()))
        }
        // Not registered, or deleted but not all certificates revoked yet.
        Err(RaError::Rejected { status: status @ (404 | 502), message }) => {
            device_list_page(ra, &user, status, None, Some(&message))
        }
        Err(err) => ra_unavailable(err),
    }
}

// Sign-in

fn sign_in_form(sessions: &mut Sessions, request: &Request) -> Reply {
    if signed_in(sessions, request).is_some() {
        return http::redirect("/enrol");
    }
    sign_in_page(sessions.cookies, 200, "", None)
}

/// Renders the sign-in form with a fresh login CSRF token, which must come
/// back both in the form and in its cookie.
fn sign_in_page(cookies: Cookies, status: u16, username: &str, error: Option<&str>) -> Reply {
    match random_token() {
        Ok(token) => http::html(status, pages::sign_in(&token, username, error))
            .with_header(cookies.set(cookies.login_csrf, &token)),
        Err(err) => {
            eprintln!("cert-enrolment: {err}");
            http::text(500, "internal error\n")
        }
    }
}

fn sign_in(config: &Config, sessions: &mut Sessions, request: &mut Request) -> Reply {
    let cookies = sessions.cookies;
    let expected_csrf = http::cookie(request, cookies.login_csrf).map(str::to_string);

    let Ok(form) = http::read_form(request) else {
        return http::text(400, "bad request\n");
    };

    let username = http::form_value(&form, "username").trim();
    let password = http::form_value(&form, "password");

    let csrf_ok = expected_csrf
        .is_some_and(|expected| tokens_match(&expected, http::form_value(&form, "csrf")));
    if !csrf_ok {
        return sign_in_page(cookies, 400, username, Some("The sign-in form expired. Please try again."));
    }

    let who = if crate::shared::user::valid_username(username) { username } else { "<invalid user name>" };

    match directory::sign_in(config, username, password) {
        Ok(SignIn::Allowed) => match sessions.create(username) {
            Ok(token) => {
                eprintln!("cert-enrolment: sign-in allowed for {who}");
                http::redirect("/enrol")
                    .with_header(cookies.set(cookies.session, &token))
                    .with_header(cookies.clear(cookies.login_csrf))
            }
            Err(err) => unavailable(&format!("sign-in for {who} failed: {err}")),
        },
        Ok(SignIn::NotEnroller) => {
            eprintln!("cert-enrolment: sign-in refused for {who}: not in the enrollers group");
            sign_in_page(cookies, 403, username, Some("Your account is not permitted to enrol devices."))
        }
        Ok(SignIn::InvalidCredentials) => {
            eprintln!("cert-enrolment: sign-in failed for {who}: invalid credentials");
            sign_in_page(cookies, 401, username, Some("Incorrect user name or password."))
        }
        Err(err) => unavailable(&format!("sign-in for {who} failed: {err}")),
    }
}

fn sign_out(sessions: &mut Sessions, request: &mut Request) -> Reply {
    let cookies = sessions.cookies;
    let Some(token) = http::cookie(request, cookies.session).map(str::to_string) else {
        return http::redirect("/login");
    };
    let Some(expected_csrf) = sessions.get(&token).map(|session| session.csrf_token.clone()) else {
        return http::redirect("/login").with_header(cookies.clear(cookies.session));
    };

    let Ok(form) = http::read_form(request) else {
        return http::text(400, "bad request\n");
    };
    if !tokens_match(&expected_csrf, http::form_value(&form, "csrf")) {
        return http::text(400, "bad request\n");
    }

    sessions.remove(&token);
    http::redirect("/login").with_header(cookies.clear(cookies.session))
}
