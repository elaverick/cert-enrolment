//! Page rendering. Every value placed into a page is HTML-escaped here.

use crate::devices::{Device, Platform};
use crate::http::escape;

pub const STYLE: &str = include_str!("pages/style.css");
const LAYOUT: &str = include_str!("pages/layout.html");

fn page(title: &str, content: &str) -> String {
    LAYOUT
        .replace("{{title}}", &escape(title))
        .replace("{{content}}", content)
}

fn message(class: &str, text: Option<&str>) -> String {
    text.map(|text| format!(r#"<p class="{class}" role="alert">{}</p>"#, escape(text)))
        .unwrap_or_default()
}

pub fn sign_in(csrf_token: &str, username: &str, error: Option<&str>) -> String {
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
            error = message("error", error),
            csrf = escape(csrf_token),
            username = escape(username),
        ),
    )
}

/// Everything the home page shows.
pub struct Home<'a> {
    pub username: &'a str,
    pub csrf_token: &'a str,
    pub devices: &'a [Device],
    pub device_domain: &'a str,
    pub zones: &'a [String],
    /// Values to refill the registration form with after an error.
    pub label: &'a str,
    pub platform: Option<Platform>,
    pub zone: &'a str,
    pub notice: Option<&'a str>,
    pub error: Option<&'a str>,
}

pub fn home(view: &Home) -> String {
    let rows: String = view
        .devices
        .iter()
        .map(|device| {
            let platform = Platform::from_id(&device.platform).map_or(device.platform.as_str(), |p| p.label());
            let status = if device.disabled { "Disabled" } else { "Enabled" };
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{status}</td></tr>\n",
                escape(&device.id),
                escape(platform),
                escape(&device.zone),
            )
        })
        .collect();

    let devices = if rows.is_empty() {
        r#"<p class="muted">No devices are registered yet.</p>"#.to_string()
    } else {
        format!(
            r#"<table>
<thead><tr><th scope="col">Device</th><th scope="col">Platform</th><th scope="col">Zone</th><th scope="col">Status</th></tr></thead>
<tbody>
{rows}</tbody>
</table>"#
        )
    };

    let platforms: String = Platform::ALL
        .iter()
        .map(|platform| {
            let selected = if view.platform == Some(*platform) { " selected" } else { "" };
            format!(r#"<option value="{}"{selected}>{}</option>"#, platform.id(), platform.label())
        })
        .collect();

    let zones: String = view
        .zones
        .iter()
        .map(|zone| {
            let selected = if zone == view.zone { " selected" } else { "" };
            format!(r#"<option value="{zone}"{selected}>{zone}</option>"#, zone = escape(zone))
        })
        .collect();

    page(
        "Device enrolment",
        &format!(
            r#"<p>Signed in as <strong>{username}</strong>.</p>
{notice}{error}
<h2>Devices</h2>
{devices}
<h2>Register a device</h2>
<form method="post" action="/devices">
<input type="hidden" name="csrf" value="{csrf}">
<label for="label">Device name</label>
<div class="suffixed">
<input type="text" id="label" name="label" value="{label}" pattern="[a-z0-9]([a-z0-9-]{{0,61}}[a-z0-9])?" maxlength="63" autocapitalize="none" spellcheck="false" required aria-describedby="label-help">
<span>.{domain}</span>
</div>
<p id="label-help" class="muted">Lowercase letters, digits and hyphens.</p>
<label for="platform">Platform</label>
<select id="platform" name="platform" required>{platforms}</select>
<label for="zone">Network zone</label>
<select id="zone" name="zone" required>{zones}</select>
<button type="submit">Register device</button>
</form>
<form method="post" action="/logout" class="sign-out">
<input type="hidden" name="csrf" value="{csrf}">
<button type="submit" class="secondary">Sign out</button>
</form>"#,
            username = escape(view.username),
            notice = message("notice", view.notice),
            error = message("error", view.error),
            csrf = escape(view.csrf_token),
            label = escape(view.label),
            domain = escape(view.device_domain),
        ),
    )
}

pub fn unavailable() -> String {
    page(
        "Directory unavailable",
        r#"<p>The directory could not be reached. Try again shortly.</p><p><a href="/">Back</a></p>"#,
    )
}
