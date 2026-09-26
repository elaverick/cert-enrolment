//! cert-enrolment - device certificate enrolment service for the homelab Wi-Fi.
//!
//! Plain HTTP only: NGINX terminates TLS for join.<domain> in front of it.

mod config;
mod devices;
mod directory;
mod http;
mod pages;
mod session;

use std::process::ExitCode;

use tiny_http::{Method, Request, Server};

use config::Config;
use devices::{Platform, Registration};
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

    match (request.method(), path.as_str()) {
        (Method::Get, "/healthz") => http::text(200, "ok\n"),
        (Method::Get, "/style.css") => http::css(pages::STYLE),
        (Method::Get, "/") => home(config, sessions, request),
        (Method::Post, "/devices") => register_device(config, sessions, request),
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

/// Values the registration form is refilled with after an error.
#[derive(Default)]
struct DeviceForm<'a> {
    label: &'a str,
    platform: Option<Platform>,
    zone: &'a str,
}

fn home(config: &Config, sessions: &mut Sessions, request: &Request) -> Reply {
    let Some(user) = signed_in(sessions, request) else {
        return http::redirect("/login");
    };

    // Set by the redirect after a successful registration.
    let registered = http::query_value(request, "registered")
        .filter(|label| devices::valid_label(label))
        .map(|label| format!("Registered {}.", devices::device_id(config, label)));

    home_page(config, &user, 200, &DeviceForm::default(), registered.as_deref(), None)
}

fn home_page(
    config: &Config,
    user: &SignedIn,
    status: u16,
    form: &DeviceForm,
    notice: Option<&str>,
    error: Option<&str>,
) -> Reply {
    let device_list = match devices::list(config) {
        Ok(device_list) => device_list,
        Err(err) => {
            eprintln!("cert-enrolment: {err}");
            return http::html(503, pages::unavailable());
        }
    };

    http::html(
        status,
        pages::home(&pages::Home {
            username: &user.username,
            csrf_token: &user.csrf_token,
            devices: &device_list,
            device_domain: &config.device_domain,
            zones: &config.device_zones,
            label: form.label,
            platform: form.platform,
            zone: form.zone,
            notice,
            error,
        }),
    )
}

fn register_device(config: &Config, sessions: &mut Sessions, request: &mut Request) -> Reply {
    let Some(user) = signed_in(sessions, request) else {
        return http::redirect("/login");
    };

    let Ok(form) = http::read_form(request) else {
        return http::text(400, "bad request\n");
    };
    if !tokens_match(&user.csrf_token, http::form_value(&form, "csrf")) {
        return http::text(400, "bad request\n");
    }

    let label = http::form_value(&form, "label").trim().to_ascii_lowercase();
    let platform = Platform::from_id(http::form_value(&form, "platform"));
    let zone = http::form_value(&form, "zone");
    let refill = DeviceForm { label: &label, platform, zone };

    let problem = if !devices::valid_label(&label) {
        Some("Device names are 1 to 63 lowercase letters, digits and hyphens, and cannot start or end with a hyphen.")
    } else if !config.device_zones.iter().any(|allowed| allowed == zone) {
        Some("Choose one of the listed network zones.")
    } else {
        None
    };
    let Some(platform) = platform.filter(|_| problem.is_none()) else {
        return home_page(config, &user, 400, &refill, None, Some(problem.unwrap_or("Choose one of the listed platforms.")));
    };

    match devices::register(config, &label, platform, zone, &user.username) {
        Ok(Registration::Registered(id)) => {
            eprintln!(
                "cert-enrolment: {} registered {id} ({}, zone {zone})",
                user.username,
                platform.id()
            );
            http::redirect(&format!("/?registered={label}"))
        }
        Ok(Registration::AlreadyExists(id)) => {
            let error = format!("{id} is already registered.");
            home_page(config, &user, 409, &refill, None, Some(&error))
        }
        Err(err) => {
            eprintln!("cert-enrolment: {err}");
            http::html(503, pages::unavailable())
        }
    }
}

fn sign_in_form(sessions: &mut Sessions, request: &Request) -> Reply {
    if http::cookie(request, SESSION_COOKIE).and_then(|token| sessions.get(token)).is_some() {
        return http::redirect("/");
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
                http::redirect("/")
                    .with_header(http::set_cookie(SESSION_COOKIE, &token))
                    .with_header(http::clear_cookie(LOGIN_CSRF_COOKIE))
            }
            Err(err) => {
                eprintln!("cert-enrolment: sign-in for {who} failed: {err}");
                http::html(503, pages::unavailable())
            }
        },
        Ok(SignIn::NotEnroller) => {
            eprintln!("cert-enrolment: sign-in refused for {who}: not in the enrollers group");
            sign_in_page(403, username, Some("Your account is not permitted to enrol devices."))
        }
        Ok(SignIn::InvalidCredentials) => {
            eprintln!("cert-enrolment: sign-in failed for {who}: invalid credentials");
            sign_in_page(401, username, Some("Incorrect user name or password."))
        }
        Err(err) => {
            eprintln!("cert-enrolment: sign-in for {who} failed: {err}");
            http::html(503, pages::unavailable())
        }
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
