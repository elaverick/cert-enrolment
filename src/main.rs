//! cert-enrolment - device certificate enrolment service for the homelab Wi-Fi.
//!
//! Plain HTTP only: NGINX terminates TLS for join.<domain> in front of it.

mod config;
mod directory;
mod http;
mod pages;
mod session;

use std::process::ExitCode;

use tiny_http::{Method, Request, Server};

use config::Config;
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
        (Method::Get, "/") => home(sessions, request),
        (Method::Get, "/login") => sign_in_form(sessions, request),
        (Method::Post, "/login") => sign_in(config, sessions, request),
        (Method::Post, "/logout") => sign_out(sessions, request),
        _ => http::text(404, "not found\n"),
    }
}

fn home(sessions: &mut Sessions, request: &Request) -> Reply {
    match http::cookie(request, SESSION_COOKIE).and_then(|token| sessions.get(token)) {
        Some(session) => http::html(200, pages::home(&session.username, &session.csrf_token)),
        None => http::redirect("/login"),
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
