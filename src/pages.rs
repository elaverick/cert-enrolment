//! Page rendering. Every value placed into a page is HTML-escaped here.

use crate::http::escape;

pub const STYLE: &str = include_str!("pages/style.css");
const LAYOUT: &str = include_str!("pages/layout.html");

fn page(title: &str, content: &str) -> String {
    LAYOUT
        .replace("{{title}}", &escape(title))
        .replace("{{content}}", content)
}

pub fn sign_in(csrf_token: &str, username: &str, error: Option<&str>) -> String {
    let error = error
        .map(|message| format!(r#"<p class="error" role="alert">{}</p>"#, escape(message)))
        .unwrap_or_default();

    page(
        "Sign in",
        &format!(
            r#"{error}<form method="post" action="/login">
<input type="hidden" name="csrf" value="{csrf}">
<label for="username">User name</label>
<input type="text" id="username" name="username" value="{username}" autocomplete="username" autocapitalize="none" spellcheck="false" required autofocus>
<label for="password">Password</label>
<input type="password" id="password" name="password" autocomplete="current-password" required>
<button type="submit">Sign in</button>
</form>"#,
            csrf = escape(csrf_token),
            username = escape(username),
        ),
    )
}

pub fn home(username: &str, csrf_token: &str) -> String {
    page(
        "Device enrolment",
        &format!(
            r#"<p>Signed in as <strong>{username}</strong>.</p>
<p class="muted">Device registration is not available yet.</p>
<form method="post" action="/logout">
<input type="hidden" name="csrf" value="{csrf}">
<button type="submit">Sign out</button>
</form>"#,
            username = escape(username),
            csrf = escape(csrf_token),
        ),
    )
}

pub fn unavailable() -> String {
    page(
        "Sign-in unavailable",
        r#"<p>The directory could not be reached. Try again shortly.</p><p><a href="/login">Back to sign in</a></p>"#,
    )
}
