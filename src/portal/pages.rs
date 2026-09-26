//! Page rendering. Every value placed into a page is HTML-escaped here.

use crate::shared::device::{Device, Platform, DESCRIPTION_MAX};
use crate::shared::http::escape;
use crate::shared::time::parse_generalized_time;

const LAYOUT: &str = include_str!("assets/layout.html");

/// Top navigation entries for a signed-in user.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Enrol,
    Devices,
    /// A page reached from a section but not itself in the navigation.
    Other,
}

/// Sign-out is a form, so it carries the session's CSRF token.
fn navigation(active: Section, csrf_token: &str) -> String {
    let link = |section: Section, href: &str, label: &str| {
        let current = if section == active { r#" aria-current="page""# } else { "" };
        format!(r#"<li><a href="{href}"{current}>{label}</a></li>"#)
    };

    format!(
        r#"<nav aria-label="Main">
<ul>
{enrol}
{devices}
<li><form method="post" action="/logout"><input type="hidden" name="csrf" value="{csrf}"><button type="submit" class="link">Sign out</button></form></li>
</ul>
</nav>"#,
        enrol = link(Section::Enrol, "/enrol", "Enrol a device"),
        devices = link(Section::Devices, "/devices", "Devices"),
        csrf = escape(csrf_token),
    )
}

struct Page<'a> {
    title: &'a str,
    subtitle: &'a str,
    /// Navigation markup, empty when signed out.
    nav: String,
    wide: bool,
    content: String,
}

fn render(page: Page) -> String {
    LAYOUT
        .replace("{{title}}", &escape(page.title))
        .replace("{{subtitle}}", &escape(page.subtitle))
        .replace("{{main_class}}", if page.wide { r#" class="wide""# } else { "" })
        .replace("{{nav}}", &page.nav)
        .replace("{{content}}", &page.content)
}

fn message(class: &str, text: Option<&str>) -> String {
    text.map(|text| format!(r#"<p class="{class}" role="alert">{}</p>"#, escape(text)))
        .unwrap_or_default()
}

/// The enrolment progress indicator. Sign-in always comes first, so it is
/// complete on every page that shows the steps.
fn steps(current: usize) -> String {
    const NAMES: [&str; 4] = ["Sign in", "Device", "Enrol", "Connect"];

    let items: String = NAMES
        .iter()
        .enumerate()
        .map(|(index, name)| {
            let number = index + 1;
            if number < current {
                format!(
                    r#"<li class="done"><span class="step-marker" aria-hidden="true">{TICK}</span>{name}<span class="visually-hidden"> (complete)</span></li>"#
                )
            } else if number == current {
                format!(r#"<li aria-current="step"><span class="step-marker" aria-hidden="true">{number}</span>{name}</li>"#)
            } else {
                format!(r#"<li><span class="step-marker" aria-hidden="true">{number}</span>{name}</li>"#)
            }
        })
        .collect();

    format!(r#"<ol class="steps" aria-label="Enrolment progress">{items}</ol>"#)
}

fn platform_label(platform: &str) -> &str {
    Platform::from_id(platform).map_or(platform, |p| p.label())
}

pub fn sign_in(csrf_token: &str, username: &str, error: Option<&str>) -> String {
    render(Page {
        title: "Sign in",
        subtitle: "Sign in with your home network account to enrol and manage devices.",
        nav: String::new(),
        wide: false,
        content: format!(
            r#"<section class="card">
{error}<form method="post" action="/login">
<input type="hidden" name="csrf" value="{csrf}">
<label for="username">User name</label>
<input type="text" id="username" name="username" value="{username}" autocomplete="username" autocapitalize="none" spellcheck="false" required autofocus>
<label for="password">Password</label>
<input type="password" id="password" name="password" autocomplete="current-password" required>
<button type="submit" class="block">Sign in</button>
</form>
</section>"#,
            error = message("error", error),
            csrf = escape(csrf_token),
            username = escape(username),
        ),
    })
}

/// The registration form, refilled after an error.
pub struct EnrolForm<'a> {
    pub csrf_token: &'a str,
    pub device_domain: &'a str,
    pub zones: &'a [String],
    pub label: &'a str,
    pub description: &'a str,
    /// Set when the server chose the platform, which the browser keeps.
    pub platform: Option<Platform>,
    pub zone: &'a str,
    pub error: Option<&'a str>,
}

pub fn enrol(form: &EnrolForm) -> String {
    let platforms: String = Platform::ALL
        .iter()
        .map(|platform| {
            let selected = if form.platform == Some(*platform) { " selected" } else { "" };
            format!(r#"<option value="{}"{selected}>{}</option>"#, platform.id(), platform.label())
        })
        .collect();

    let zones: String = form
        .zones
        .iter()
        .map(|zone| {
            let selected = if zone == form.zone { " selected" } else { "" };
            format!(r#"<option value="{zone}"{selected}>{zone}</option>"#, zone = escape(zone))
        })
        .collect();

    let chosen = if form.platform.is_some() { r#" data-chosen="1""# } else { "" };

    render(Page {
        title: "Connect a new device",
        subtitle: "Enrol a device certificate to securely connect to the trusted Wi-Fi.",
        nav: navigation(Section::Enrol, form.csrf_token),
        wide: false,
        content: format!(
            r#"{steps}
<section class="card" aria-labelledby="identify">
<h2 id="identify">2. Identify your device</h2>
<p class="muted">Tell us about the device you’re connecting so we can issue a device certificate.</p>
{error}<form method="post" action="/enrol">
<input type="hidden" name="csrf" value="{csrf}">
<div class="card-body">
<div>
<label for="platform">Device type</label>
<select id="platform" name="platform" required{chosen}>{platforms}</select>
<p id="platform-detected" class="hint" hidden>Detected from this browser.</p>
<label for="label">Device name</label>
<div class="suffixed">
<input type="text" id="label" name="label" value="{label}" pattern="[a-z0-9]([a-z0-9\-]{{0,61}}[a-z0-9])?" maxlength="63" autocapitalize="none" spellcheck="false" required aria-describedby="label-hint">
<span>.{domain}</span>
</div>
<p id="label-hint" class="hint">Lowercase letters, digits and hyphens, such as ed-laptop.
<span data-tip="windows" hidden>This PC’s name is under Settings › System › About.</span>
<span data-tip="linux" hidden>Run <code>hostname</code> to see this computer’s name.</span>
<span data-tip="ios" hidden>This device’s name is under Settings › General › About › Name.</span></p>
<label for="description">Description <span class="optional">(optional)</span></label>
<input type="text" id="description" name="description" value="{description}" maxlength="{description_max}" aria-describedby="description-hint">
<p id="description-hint" class="hint">A friendly name to help you recognise this device later.</p>
<label for="zone">Network zone</label>
<select id="zone" name="zone" required>{zones}</select>
</div>
<div class="illustration" aria-hidden="true">{computer}{phone}</div>
</div>
<button type="submit" class="block">Continue {arrow}</button>
</form>
<hr>
<div class="next">
<h3>What happens next?</h3>
<ol>
<li><span class="step-marker" aria-hidden="true">3</span><strong>Enrol the device</strong><span class="detail">We’ll issue and install a device certificate.</span></li>
<li><span class="step-marker" aria-hidden="true">4</span><strong>Connect to Wi-Fi</strong><span class="detail">Your device will join the trusted Wi-Fi network automatically.</span></li>
</ol>
</div>
</section>"#,
            steps = steps(2),
            error = message("error", form.error),
            csrf = escape(form.csrf_token),
            label = escape(form.label),
            domain = escape(form.device_domain),
            description = escape(form.description),
            description_max = DESCRIPTION_MAX,
            computer = COMPUTER_ILLUSTRATION,
            phone = PHONE_ILLUSTRATION,
            arrow = ARROW,
        ),
    })
}

/// Step 3: how to enrol a registered device, with its enrolment script.
pub fn enrolled(device: &Device, csrf_token: &str, error: Option<&str>) -> String {
    let description = if device.description.is_empty() {
        String::new()
    } else {
        format!("<dt>Description</dt><dd>{}</dd>", escape(&device.description))
    };

    let instructions = match Platform::from_id(&device.platform) {
        Some(Platform::Windows) => script_instructions(
            device,
            csrf_token,
            "Download the enrolment script on this Windows computer, then open PowerShell as administrator in the folder you saved it to and run:",
            &format!("powershell -ExecutionPolicy Bypass -File .\\enrol-{}.ps1", device.label),
            "It trusts the network’s Root CA, creates a key in the TPM, installs the device certificate, adds the Wi-Fi profile and schedules renewal.",
        ),
        Some(Platform::Linux) => script_instructions(
            device,
            csrf_token,
            "Download the enrolment script on this Linux computer, then run it as root from the folder you saved it to:",
            &format!("sudo sh ./enrol-{}.sh", device.label),
            "It saves the network’s Root CA, creates a key readable only by root, installs the device certificate, adds a NetworkManager profile and a renewal timer.",
        ),
        _ => format!(
            r#"<p>Enrolment for {} is not available yet. The device is registered and appears under Devices.</p>"#,
            escape(platform_label(&device.platform))
        ),
    };

    render(Page {
        title: "Connect a new device",
        subtitle: "Enrol a device certificate to securely connect to the trusted Wi-Fi.",
        nav: navigation(Section::Other, csrf_token),
        wide: false,
        content: format!(
            r#"{steps}
<section class="card" aria-labelledby="enrol">
<h2 id="enrol">3. Enrol the device</h2>
{error}<dl class="summary">
<dt>Device</dt><dd>{id}</dd>
{description}
<dt>Type</dt><dd>{platform}</dd>
<dt>Zone</dt><dd>{zone}</dd>
</dl>
{instructions}
<hr>
<div class="next">
<h3>What happens next?</h3>
<ol>
<li><span class="step-marker" aria-hidden="true">4</span><strong>Connect to Wi-Fi</strong><span class="detail">Once enrolled, the device joins the trusted Wi-Fi automatically when it is in range, and renews its certificate by itself.</span></li>
</ol>
</div>
<a href="/devices" class="button secondary">Go to devices</a>
</section>"#,
            steps = steps(3),
            error = message("error", error),
            id = escape(&device.id),
            platform = escape(platform_label(&device.platform)),
            zone = escape(&device.zone),
        ),
    })
}

fn script_instructions(device: &Device, csrf_token: &str, before: &str, command: &str, after: &str) -> String {
    format!(
        r#"<p>{before}</p>
<pre class="command"><code>{command}</code></pre>
<p class="muted">{after} The script works once, within ten minutes of downloading; download it again if it expires.</p>
<form method="post" action="/enrol/download">
<input type="hidden" name="csrf" value="{csrf}">
<input type="hidden" name="device" value="{label}">
<button type="submit" class="block">Download enrolment script {arrow}</button>
</form>"#,
        before = escape(before),
        command = escape(command),
        after = escape(after),
        csrf = escape(csrf_token),
        label = escape(&device.label),
        arrow = ARROW,
    )
}

/// Devices renew once two thirds of a certificate's life has passed, ten days
/// before expiry for a 30-day certificate, and try daily. A certificate this
/// close to expiry has missed several renewals.
const EXPIRY_WARNING_DAYS: i64 = 7;

/// The Certificate cell: when the newest certificate expires, flagged once
/// renewal looks to have stopped. `now` is seconds since the Unix epoch.
fn certificate_status(expires: Option<&str>, now: i64) -> String {
    let Some((text, unix)) = expires.and_then(|text| Some((text, parse_generalized_time(text)?))) else {
        return r#"<span class="muted">Not enrolled</span>"#.to_string();
    };

    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let month = MONTHS[text[4..6].parse::<usize>().unwrap_or(1) - 1];
    let date = format!(
        r#"<time datetime="{}-{}-{}T{}:{}:{}Z">{} {month} {}</time>"#,
        &text[0..4],
        &text[4..6],
        &text[6..8],
        &text[8..10],
        &text[10..12],
        &text[12..14],
        text[6..8].trim_start_matches('0'),
        &text[0..4],
    );

    if unix <= now {
        return format!(r#"<span class="status-expired">Expired {date}</span><span class="detail">Enrol the device again.</span>"#);
    }
    let days = (unix - now) / 86_400;
    let remaining = match days {
        0 => "today".to_string(),
        1 => "tomorrow".to_string(),
        days => format!("in {days} days"),
    };
    if days < EXPIRY_WARNING_DAYS {
        format!(r#"<span class="status-warning">Expires {date}</span><span class="detail">{remaining}, renewal overdue</span>"#)
    } else {
        format!(r#"Expires {date}<span class="detail">{remaining}</span>"#)
    }
}

pub fn devices(devices: &[Device], csrf_token: &str, now: i64, notice: Option<&str>, error: Option<&str>) -> String {
    let rows: String = devices
        .iter()
        .map(|device| {
            let (status, toggle_action, toggle_label) = if device.disabled {
                (r#"<span class="status-disabled">Disabled</span>"#, "enable", "Enable")
            } else {
                ("Enabled", "disable", "Disable")
            };
            let description = if device.description.is_empty() {
                String::new()
            } else {
                format!(r#"<span class="detail">{}</span>"#, escape(&device.description))
            };
            format!(
                r#"<tr><td>{id}{description}</td><td data-label="Type">{platform}</td><td data-label="Zone">{zone}</td><td data-label="Status">{status}</td><td data-label="Certificate">{certificate}</td><td class="actions">{enrol}{toggle}{delete}</td></tr>
"#,
                id = escape(&device.id),
                platform = escape(platform_label(&device.platform)),
                zone = escape(&device.zone),
                certificate = certificate_status(device.certificate_expires.as_deref(), now),
                enrol = if device.disabled || device.label.is_empty() {
                    String::new()
                } else {
                    format!(
                        r#"<a href="/enrol/device?device={label}" class="button small secondary" aria-label="Enrol {id}">Enrol</a>"#,
                        label = escape(&device.label),
                        id = escape(&device.id),
                    )
                },
                toggle = action_form(toggle_action, toggle_label, &device.id, csrf_token, "secondary"),
                delete = action_form("delete", "Delete", &device.id, csrf_token, "danger"),
            )
        })
        .collect();

    let list = if rows.is_empty() {
        r#"<p class="muted">No devices are registered yet. <a href="/enrol">Enrol a device</a>.</p>"#.to_string()
    } else {
        format!(
            r#"<div class="table-wrap"><table>
<thead><tr><th scope="col">Device</th><th scope="col">Type</th><th scope="col">Zone</th><th scope="col">Status</th><th scope="col">Certificate</th><th scope="col"><span class="visually-hidden">Actions</span></th></tr></thead>
<tbody>
{rows}</tbody>
</table></div>"#
        )
    };

    render(Page {
        title: "Devices",
        subtitle: "Devices registered for the trusted Wi-Fi. Disabled devices are refused at their next connection.",
        nav: navigation(Section::Devices, csrf_token),
        wide: true,
        content: format!(
            r#"<section class="card" aria-label="Registered devices">
{notice}{error}{list}
</section>"#,
            notice = message("notice", notice),
            error = message("error", error),
        ),
    })
}

/// A one-button form that posts a device id to /devices/<action>. The
/// accessible name includes the device, since the buttons repeat per row.
fn action_form(action: &str, label: &str, id: &str, csrf_token: &str, class: &str) -> String {
    format!(
        r#"<form method="post" action="/devices/{action}">
<input type="hidden" name="csrf" value="{csrf}">
<input type="hidden" name="id" value="{id}">
<button type="submit" class="small {class}" aria-label="{label} {id}">{label}</button>
</form>"#,
        csrf = escape(csrf_token),
        id = escape(id),
    )
}

pub fn confirm_delete(id: &str, csrf_token: &str) -> String {
    render(Page {
        title: "Delete device",
        subtitle: "Deleted devices can no longer join the trusted Wi-Fi.",
        nav: navigation(Section::Devices, csrf_token),
        wide: false,
        content: format!(
            r#"<section class="card">
<p>Delete <strong>{id}</strong>?</p>
<p class="muted">To use it again, you will need to enrol it again.</p>
<form method="post" action="/devices/delete">
<input type="hidden" name="csrf" value="{csrf}">
<input type="hidden" name="id" value="{id}">
<input type="hidden" name="confirm" value="yes">
<div class="button-row">
<button type="submit" class="danger">Delete device</button>
<a href="/devices" class="button secondary">Cancel</a>
</div>
</form>
</section>"#,
            id = escape(id),
            csrf = escape(csrf_token),
        ),
    })
}

/// The plain-HTTP onboarding page: trust the Root CA, then continue to the
/// portal over HTTPS. One section per platform; the page script opens the
/// one for this device.
pub fn onboarding(common_name: &str, fingerprint: &str, public_url: &str) -> String {
    let name = escape(common_name);
    let host = public_url.trim_start_matches("https://");

    render(Page {
        title: "Set up this device",
        subtitle: "Trust this network’s certificate authority, then enrol the device for the trusted Wi-Fi.",
        nav: String::new(),
        wide: false,
        content: format!(
            r#"<section class="card" aria-labelledby="trust">
<h2 id="trust">1. Trust the Root CA</h2>
<p class="muted">The enrolment site uses a certificate from this network’s own certificate authority. Install its Root CA on this device first.</p>
<dl class="summary">
<dt>Root CA</dt><dd>{name}</dd>
<dt>SHA-256</dt><dd><code class="fingerprint">{fingerprint}</code></dd>
</dl>
<p class="hint">This page is not encrypted. If in doubt, compare the fingerprint with one from someone you trust before installing.</p>

<details class="platform" data-platform="windows" open>
<summary>Windows</summary>
<a href="/root-ca.cer" class="button block" download>Download the Root CA</a>
<p>Open PowerShell as administrator in the folder you saved it to, and run:</p>
<pre class="command"><code>certutil -addstore Root .\root-ca.cer</code></pre>
<p class="muted">To check it first, <code>Get-FileHash .\root-ca.cer</code> shows the same fingerprint without spaces.</p>
</details>

<details class="platform" data-platform="ios" open>
<summary>iPhone / iPad</summary>
<p>Profiles cannot be installed from a Wi-Fi sign-in window. If this page opened in one, tap Cancel, choose to use the network without internet, then open <strong>Safari</strong> and go to <code>http://{host}/</code>.</p>
<a href="/root-ca.mobileconfig" class="button block">Download the profile</a>
<ol class="instructions">
<li>Open Settings › Profile Downloaded, and install it. Its details show the fingerprint.</li>
<li>Go to Settings › General › About › Certificate Trust Settings, and turn on full trust for <strong>{name}</strong>.</li>
</ol>
<p class="muted">Enrolment for iPhone and iPad is not available yet.</p>
</details>

<details class="platform" data-platform="linux" open>
<summary>Linux</summary>
<a href="/root-ca.crt" class="button block" download>Download the Root CA</a>
<p>From the folder you saved it to, on Debian or Ubuntu:</p>
<pre class="command"><code>sudo cp root-ca.crt /usr/local/share/ca-certificates/cert-enrolment-root-ca.crt
sudo update-ca-certificates</code></pre>
<p>On Fedora:</p>
<pre class="command"><code>sudo cp root-ca.crt /etc/pki/ca-trust/source/anchors/cert-enrolment-root-ca.crt
sudo update-ca-trust</code></pre>
<p class="muted">To check it first, <code>openssl x509 -in root-ca.crt -noout -fingerprint -sha256</code>. Firefox keeps its own list: import it under Settings › Privacy &amp; Security › Certificates.</p>
</details>
</section>

<section class="card" aria-labelledby="continue">
<h2 id="continue">2. Continue to enrolment</h2>
<p class="muted">Sign in over HTTPS to register and enrol this device. If your browser warns about the site’s certificate, the Root CA is not trusted yet.</p>
<a href="{url}/" class="button block">Continue to {host} {arrow}</a>
</section>"#,
            fingerprint = escape(fingerprint),
            host = escape(host),
            url = escape(public_url),
            arrow = ARROW,
        ),
    })
}

pub fn unavailable() -> String {
    render(Page {
        title: "Directory unavailable",
        subtitle: "The directory could not be reached. Try again shortly.",
        nav: String::new(),
        wide: false,
        content: r#"<section class="card"><a href="/" class="button secondary">Try again</a></section>"#.to_string(),
    })
}

const TICK: &str = r#"<svg viewBox="0 0 16 16" width="14" height="14" focusable="false"><path d="M3 8.5l3.2 3L13 4.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>"#;

const ARROW: &str = r#"<svg viewBox="0 0 20 20" width="18" height="18" aria-hidden="true" focusable="false"><path d="M3 10h13M11 5l5 5-5 5" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>"#;

const COMPUTER_ILLUSTRATION: &str = r#"<svg data-illustration="computer" viewBox="0 0 180 130" focusable="false">
<path d="M38 12h110a4 4 0 0 1 4 4l-8 86H30l4-86a4 4 0 0 1 4-4z" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linejoin="round"/>
<path d="M42 20h100l-7 74H37z" fill="none" stroke="currentColor" stroke-width="1" opacity=".5"/>
<path d="M6 104h168l-6 10H14z" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linejoin="round"/>
<path d="M74 108h32" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
</svg>"#;

const PHONE_ILLUSTRATION: &str = r#"<svg data-illustration="phone" viewBox="0 0 180 130" focusable="false" hidden>
<rect x="62" y="6" width="56" height="118" rx="10" fill="none" stroke="currentColor" stroke-width="2.2"/>
<rect x="67" y="18" width="46" height="94" rx="3" fill="none" stroke="currentColor" stroke-width="1" opacity=".5"/>
<path d="M82 12h16" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
</svg>"#;

#[cfg(test)]
mod tests {
    use super::*;

    // 2026-09-26T12:00:00Z
    const NOW: i64 = 1_790_424_000;

    #[test]
    fn certificate_status_reports_expiry() {
        assert!(certificate_status(None, NOW).contains("Not enrolled"));
        assert!(certificate_status(Some("garbage"), NOW).contains("Not enrolled"));

        let valid = certificate_status(Some("20261026185120Z"), NOW);
        assert!(valid.contains(r#"<time datetime="2026-10-26T18:51:20Z">26 Oct 2026</time>"#), "{valid}");
        assert!(valid.contains("in 30 days"));
        assert!(!valid.contains("status-"));

        let soon = certificate_status(Some("20261001120000Z"), NOW);
        assert!(soon.contains("status-warning") && soon.contains("in 5 days"), "{soon}");
        assert!(certificate_status(Some("20260927130000Z"), NOW).contains("tomorrow"));
        assert!(certificate_status(Some("20260926130000Z"), NOW).contains("today"));

        let expired = certificate_status(Some("20260901090000Z"), NOW);
        assert!(expired.contains("status-expired") && expired.contains("1 Sep 2026"), "{expired}");
    }
}
