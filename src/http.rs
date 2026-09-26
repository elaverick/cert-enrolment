//! HTTP helpers: form and cookie parsing, responses and HTML escaping.

use std::io::{Cursor, Read};

use tiny_http::{Header, Request, Response};

pub type Reply = Response<Cursor<Vec<u8>>>;

/// Largest request body accepted; sign-in forms are far smaller.
const MAX_BODY: u64 = 8 * 1024;

pub const SESSION_COOKIE: &str = "__Host-session";
pub const LOGIN_CSRF_COOKIE: &str = "__Host-login-csrf";

/// Reads an application/x-www-form-urlencoded body into name/value pairs.
pub fn read_form(request: &mut Request) -> Result<Vec<(String, String)>, ()> {
    let is_form = header(request, "Content-Type")
        .is_some_and(|value| value.starts_with("application/x-www-form-urlencoded"));
    if !is_form {
        return Err(());
    }

    let mut body = Vec::new();
    request
        .as_reader()
        .take(MAX_BODY + 1)
        .read_to_end(&mut body)
        .map_err(|_| ())?;
    if body.len() as u64 > MAX_BODY {
        return Err(());
    }

    let body = String::from_utf8(body).map_err(|_| ())?;
    body.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            Ok((percent_decode(name)?, percent_decode(value)?))
        })
        .collect()
}

pub fn form_value<'a>(form: &'a [(String, String)], name: &str) -> &'a str {
    form.iter()
        .find(|(field, _)| field == name)
        .map_or("", |(_, value)| value.as_str())
}

fn percent_decode(input: &str) -> Result<String, ()> {
    let mut bytes = Vec::with_capacity(input.len());
    let mut iter = input.bytes();
    while let Some(b) = iter.next() {
        match b {
            b'+' => bytes.push(b' '),
            b'%' => {
                let hex = [iter.next().ok_or(())?, iter.next().ok_or(())?];
                let hex = std::str::from_utf8(&hex).map_err(|_| ())?;
                bytes.push(u8::from_str_radix(hex, 16).map_err(|_| ())?);
            }
            _ => bytes.push(b),
        }
    }
    String::from_utf8(bytes).map_err(|_| ())
}

/// Reads a query string parameter. Values are used only after validation,
/// so percent-encoded values are not decoded.
pub fn query_value<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    request
        .url()
        .split_once('?')?
        .1
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(field, _)| *field == name)
        .map(|(_, value)| value)
}

pub fn header<'a>(request: &'a Request, name: &'static str) -> Option<&'a str> {
    request
        .headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str())
}

pub fn cookie<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    header(request, "Cookie")?
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(cookie, _)| *cookie == name)
        .map(|(_, value)| value)
}

/// Cookies are host-only, HTTPS-only, hidden from scripts and never sent on
/// cross-site requests.
pub fn set_cookie(name: &str, value: &str) -> Header {
    raw_header(
        "Set-Cookie",
        &format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Strict"),
    )
}

pub fn clear_cookie(name: &str) -> Header {
    raw_header(
        "Set-Cookie",
        &format!("{name}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"),
    )
}

pub fn html(status: u16, body: String) -> Reply {
    secure(Response::from_string(body).with_status_code(status))
        .with_header(raw_header("Content-Type", "text/html; charset=utf-8"))
}

pub fn text(status: u16, body: &str) -> Reply {
    secure(Response::from_string(body).with_status_code(status))
        .with_header(raw_header("Content-Type", "text/plain; charset=utf-8"))
}

/// A static asset embedded in the binary. Assets change only with a new
/// image, so they may be cached briefly.
pub fn asset(content_type: &str, body: &[u8]) -> Reply {
    headers(Response::from_data(body.to_vec()))
        .with_header(raw_header("Content-Type", content_type))
        .with_header(raw_header("Cache-Control", "public, max-age=3600"))
}

/// 303 so that a POST is followed by a GET.
pub fn redirect(location: &str) -> Reply {
    secure(Response::from_string("").with_status_code(303))
        .with_header(raw_header("Location", location))
}

/// Pages and redirects are personal, so they are never cached.
fn secure(response: Reply) -> Reply {
    headers(response).with_header(raw_header("Cache-Control", "no-store"))
}

fn headers(response: Reply) -> Reply {
    response
        .with_header(raw_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; \
             form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ))
        .with_header(raw_header("X-Content-Type-Options", "nosniff"))
        .with_header(raw_header("Referrer-Policy", "no-referrer"))
}

fn raw_header(name: &str, value: &str) -> Header {
    Header::from_bytes(name, value).expect("header names and values are ASCII")
}

pub fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(c),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_form_encoding() {
        assert_eq!(percent_decode("a+b%21%C3%A9").unwrap(), "a b!é");
        assert!(percent_decode("%4").is_err());
        assert!(percent_decode("%zz").is_err());
        assert!(percent_decode("%ff").is_err());
    }

    #[test]
    fn escapes_html() {
        assert_eq!(escape(r#"<a href="x">'&'</a>"#), "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;");
    }
}
