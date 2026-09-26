//! cert-enrolment - device certificate enrolment for an 802.1X (EAP-TLS) Wi-Fi network.
//!
//! Plain HTTP only: NGINX terminates TLS for join.<domain> in front of it.

mod assets;
mod config;
mod devices;
mod directory;
mod http;
mod pages;
mod session;

use std::process::ExitCode;

use tiny_http::{Method, Request, Server};

use config::Config;
use devices::{Change, Platform, Registration};
use directory::SignIn;
use http::{Reply, LOGIN_CSRF_COOKIE, SESSION_COOKIE};
use session::{random_token, tokens_match, Sessions};

fn main() -> ExitCode {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("cert-enrolment: {err}");
            return ExitCode::FAILURE;
        }
    };

    let server = match Server::http(&config.listen) {
        Ok(server) => server,
        Err(err) => {
            eprintln!("cert-enrolment: cannot listen on {}: {err}", config.listen);
            return ExitCode::FAILURE;
        }
    };

    eprintln!("cert-enrolment: listening on {}", config.listen);

    let mut sessions = Sessions::new(config.session_idle);

    for mut request in server.incoming_requests() {
        let response = route(&config, &mut sessions, &mut request);

        if let Err(err) = request.respond(response) {
            eprintln!("cert-enrolment: failed to send response: {err}");
        }
    }

    ExitCode::SUCCESS
}

fn route(config: &Config, sessions: &mut Sessions, request: &mut Request) -> Reply {
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
        (Method::Post, "/enrol") => register_device(config, sessions, request),
        (Method::Get, "/enrol/device") => enrolled(config, sessions, request),
        (Method::Get, "/devices") => device_list(config, sessions, request),
        (Method::Post, "/devices/disable") => device_action(config, sessions, request, Action::Disable),
        (Method::Post, "/devices/enable") => device_action(config, sessions, request, Action::Enable),
        (Method::Post, "/devices/delete") => device_action(config, sessions, request, Action::Delete),
        (Method::Get, "/login") => sign_in_form(sessions, request),
        (Method::Post, "/login") => sign_in(config, sessions, request),
        (Method::Post, "/logout") => sign_out(sessions, request),
        _ => http::text(404, "not found\n"),
    }
}

/// The signed-in user and their CSRF token, copied out of the session.
struct SignedIn {
    username: String,
    csrf_token: String,
}

fn signed_in(sessions: &mut Sessions, request: &Request) -> Option<SignedIn> {
    let session = sessions.get(http::cookie(request, SESSION_COOKIE)?)?;
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

fn register_device(config: &Config, sessions: &mut Sessions, request: &mut Request) -> Reply {
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

    let problem = if !devices::valid_label(&label) {
        Some("Device names are 1 to 63 lowercase letters, digits and hyphens, and cannot start or end with a hyphen.")
    } else if !devices::valid_description(description) {
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

    match devices::register(config, &label, description, platform, zone, &user.username) {
        Ok(Registration::Registered(id)) => {
            eprintln!("cert-enrolment: {} registered {id} ({}, zone {zone})", user.username, platform.id());
            http::redirect(&format!("/enrol/device?device={label}"))
        }
        Ok(Registration::AlreadyExists(id)) => {
            let error = format!("{id} is already registered.");
            enrol_page(config, &user, 409, &refill, Some(&error))
        }
        Err(err) => unavailable(&err),
    }
}

/// Step 3 for a registered device, named by the validated `device` query
/// parameter.
fn enrolled(config: &Config, sessions: &mut Sessions, request: &Request) -> Reply {
    let Some(user) = signed_in(sessions, request) else {
        return http::redirect("/login");
    };
    let Some(label) = http::query_value(request, "device").filter(|label| devices::valid_label(label)) else {
        return http::redirect("/enrol");
    };

    match devices::get(config, label) {
        Ok(Some(device)) => http::html(200, pages::enrolled(&device, &user.csrf_token)),
        Ok(None) => http::redirect("/enrol"),
        Err(err) => unavailable(&err),
    }
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

fn device_list(config: &Config, sessions: &mut Sessions, request: &Request) -> Reply {
    let Some(user) = signed_in(sessions, request) else {
        return http::redirect("/login");
    };

    // Set by the redirect after a change. Both values are validated, so
    // nothing from the URL reaches the page unchecked.
    let notice = http::query_value(request, "device")
        .filter(|label| devices::valid_label(label))
        .zip(http::query_value(request, "done").and_then(|done| Action::ALL.into_iter().find(|a| a.done() == done)))
        .map(|(label, action)| format!("{} {}.", action.past_tense(), devices::device_id(config, label)));

    device_list_page(config, &user, 200, notice.as_deref(), None)
}

fn device_list_page(config: &Config, user: &SignedIn, status: u16, notice: Option<&str>, error: Option<&str>) -> Reply {
    match devices::list(config) {
        Ok(device_list) => http::html(status, pages::devices(&device_list, &user.csrf_token, notice, error)),
        Err(err) => unavailable(&err),
    }
}

/// Disables, enables or deletes the device named by the form's `id`.
/// Deleting first shows a confirmation page, which posts back with
/// `confirm=yes`.
fn device_action(config: &Config, sessions: &mut Sessions, request: &mut Request, action: Action) -> Reply {
    let Some(user) = signed_in(sessions, request) else {
        return http::redirect("/login");
    };
    let Some(form) = session_form(request, &user) else {
        return http::text(400, "bad request\n");
    };

    let id = http::form_value(&form, "id");
    let Some(label) = devices::label_from_id(&config.device_domain, id) else {
        return device_list_page(config, &user, 400, None, Some("That is not a device name."));
    };

    let result = match action {
        Action::Delete if http::form_value(&form, "confirm") != "yes" => {
            return http::html(200, pages::confirm_delete(id, &user.csrf_token));
        }
        Action::Delete => devices::delete(config, label),
        Action::Disable => devices::set_disabled(config, label, true),
        Action::Enable => devices::set_disabled(config, label, false),
    };

    match result {
        Ok(Change::Done) => {
            eprintln!("cert-enrolment: {} {} {id}", user.username, action.done());
            http::redirect(&format!("/devices?done={}&device={label}", action.done()))
        }
        Ok(Change::NotFound) => {
            let error = format!("{id} is not registered.");
            device_list_page(config, &user, 404, None, Some(&error))
        }
        Err(err) => unavailable(&err),
    }
}

// Sign-in

fn sign_in_form(sessions: &mut Sessions, request: &Request) -> Reply {
    if signed_in(sessions, request).is_some() {
        return http::redirect("/enrol");
    }
    sign_in_page(200, "", None)
}

/// Renders the sign-in form with a fresh login CSRF token, which must come
/// back both in the form and in its cookie.
fn sign_in_page(status: u16, username: &str, error: Option<&str>) -> Reply {
    match random_token() {
        Ok(token) => http::html(status, pages::sign_in(&token, username, error))
            .with_header(http::set_cookie(LOGIN_CSRF_COOKIE, &token)),
        Err(err) => {
            eprintln!("cert-enrolment: {err}");
            http::text(500, "internal error\n")
        }
    }
}

fn sign_in(config: &Config, sessions: &mut Sessions, request: &mut Request) -> Reply {
    let expected_csrf = http::cookie(request, LOGIN_CSRF_COOKIE).map(str::to_string);

    let Ok(form) = http::read_form(request) else {
        return http::text(400, "bad request\n");
    };

    let username = http::form_value(&form, "username").trim();
    let password = http::form_value(&form, "password");

    let csrf_ok = expected_csrf
        .is_some_and(|expected| tokens_match(&expected, http::form_value(&form, "csrf")));
    if !csrf_ok {
        return sign_in_page(400, username, Some("The sign-in form expired. Please try again."));
    }

    let who = if directory::valid_username(username) { username } else { "<invalid user name>" };

    match directory::sign_in(config, username, password) {
        Ok(SignIn::Allowed) => match sessions.create(username) {
            Ok(token) => {
                eprintln!("cert-enrolment: sign-in allowed for {who}");
                http::redirect("/enrol")
                    .with_header(http::set_cookie(SESSION_COOKIE, &token))
                    .with_header(http::clear_cookie(LOGIN_CSRF_COOKIE))
            }
            Err(err) => unavailable(&format!("sign-in for {who} failed: {err}")),
        },
        Ok(SignIn::NotEnroller) => {
            eprintln!("cert-enrolment: sign-in refused for {who}: not in the enrollers group");
            sign_in_page(403, username, Some("Your account is not permitted to enrol devices."))
        }
        Ok(SignIn::InvalidCredentials) => {
            eprintln!("cert-enrolment: sign-in failed for {who}: invalid credentials");
            sign_in_page(401, username, Some("Incorrect user name or password."))
        }
        Err(err) => unavailable(&format!("sign-in for {who} failed: {err}")),
    }
}

fn sign_out(sessions: &mut Sessions, request: &mut Request) -> Reply {
    let Some(token) = http::cookie(request, SESSION_COOKIE).map(str::to_string) else {
        return http::redirect("/login");
    };
    let Some(expected_csrf) = sessions.get(&token).map(|session| session.csrf_token.clone()) else {
        return http::redirect("/login").with_header(http::clear_cookie(SESSION_COOKIE));
    };

    let Ok(form) = http::read_form(request) else {
        return http::text(400, "bad request\n");
    };
    if !tokens_match(&expected_csrf, http::form_value(&form, "csrf")) {
        return http::text(400, "bad request\n");
    }

    sessions.remove(&token);
    http::redirect("/login").with_header(http::clear_cookie(SESSION_COOKIE))
}
