//! join - device enrollment service for the homelab Wi-Fi.
//!
//! Plain HTTP only: NGINX terminates TLS for join.<domain> in front of it.

use std::env;
use std::process::ExitCode;

use tiny_http::{Header, Method, Response, Server};

const DEFAULT_LISTEN: &str = "0.0.0.0:8080";

fn main() -> ExitCode {
    let listen = env::var("JOIN_LISTEN").unwrap_or_else(|_| DEFAULT_LISTEN.to_string());

    let server = match Server::http(&listen) {
        Ok(server) => server,
        Err(err) => {
            eprintln!("join: cannot listen on {listen}: {err}");
            return ExitCode::FAILURE;
        }
    };

    eprintln!("join: listening on {listen}");

    for request in server.incoming_requests() {
        let response = match (request.method(), request.url()) {
            (Method::Get, "/healthz") => text(200, "ok\n"),
            _ => text(404, "not found\n"),
        };

        if let Err(err) = request.respond(response) {
            eprintln!("join: failed to send response: {err}");
        }
    }

    ExitCode::SUCCESS
}

fn text(status: u16, body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let content_type = Header::from_bytes("Content-Type", "text/plain; charset=utf-8")
        .expect("static header is valid");

    Response::from_string(body)
        .with_status_code(status)
        .with_header(content_type)
}
