//! Enrolment scripts for Windows and Linux.
//!
//! Each download is a script with the device's values and a fresh
//! single-use token written in. Every value is checked at start-up or
//! registration (device names, the CA URL, the SSID, the RADIUS server name
//! and the Root CA all have restricted formats), and is also quoted for the
//! script language, so no value can change the script's meaning.

use super::config::Config;
use super::devices::Platform;

const WINDOWS: &str = include_str!("assets/enrol-windows.ps1");
const LINUX: &str = include_str!("assets/enrol-linux.sh");

pub struct Script {
    pub file_name: String,
    pub content_type: &'static str,
    pub body: String,
}

/// Renders the enrolment script for a device, or `None` for platforms that
/// are not enrolled by script.
pub fn script(config: &Config, platform: Platform, label: &str, device_id: &str, token: &str) -> Option<Script> {
    match platform {
        Platform::Windows => {
            let body = fill(WINDOWS, config, label, device_id, token, powershell_quote)
                .replace("\r\n", "\n")
                .replace('\n', "\r\n");
            Some(Script {
                file_name: format!("enrol-{label}.ps1"),
                content_type: "text/plain; charset=us-ascii",
                body,
            })
        }
        Platform::Linux => Some(Script {
            file_name: format!("enrol-{label}.sh"),
            content_type: "text/x-shellscript; charset=us-ascii",
            body: fill(LINUX, config, label, device_id, token, shell_quote).replace("\r\n", "\n"),
        }),
        Platform::Ios => None,
    }
}

/// Fills a template. Values inside single-quoted string literals are quoted
/// with `quote`; the rest (label, device id, Root CA) are restricted to
/// characters that need no quoting.
fn fill(template: &str, config: &Config, label: &str, device_id: &str, token: &str, quote: fn(&str) -> String) -> String {
    template
        .replace("{{LABEL}}", label)
        .replace("'{{DEVICE_ID}}'", &quote(device_id))
        .replace("{{DEVICE_ID}}", device_id)
        .replace("'{{CA_URL}}'", &quote(&config.ca_url))
        .replace("'{{TOKEN}}'", &quote(token))
        .replace("'{{SSID}}'", &quote(&config.wifi_ssid))
        .replace("'{{RADIUS_SERVER_NAME}}'", &quote(&config.radius_server_name))
        .replace("{{ROOT_CA_PEM}}", &config.root_ca_pem)
}

/// A PowerShell single-quoted string. PowerShell also treats the typographic
/// single quotes as quote characters, so all of them are doubled.
fn powershell_quote(value: &str) -> String {
    let mut quoted = String::from("'");
    for c in value.chars() {
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}') {
            quoted.push(c);
        }
        quoted.push(c);
    }
    quoted.push('\'');
    quoted
}

/// A POSIX shell single-quoted string.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_for_powershell() {
        assert_eq!(powershell_quote("Home"), "'Home'");
        assert_eq!(powershell_quote("Ed's Wi-Fi"), "'Ed''s Wi-Fi'");
        assert_eq!(powershell_quote("Ed\u{2019}s"), "'Ed\u{2019}\u{2019}s'");
        assert_eq!(powershell_quote("$(evil) `x"), "'$(evil) `x'");
    }

    #[test]
    fn quotes_for_shell() {
        assert_eq!(shell_quote("Home"), "'Home'");
        assert_eq!(shell_quote("Ed's $(evil)"), r"'Ed'\''s $(evil)'");
    }

    #[test]
    fn templates_have_every_placeholder_quoted() {
        for (name, template) in [("windows", WINDOWS), ("linux", LINUX)] {
            for field in ["DEVICE_ID", "CA_URL", "TOKEN", "SSID", "RADIUS_SERVER_NAME"] {
                assert!(template.contains(&format!("'{{{{{field}}}}}'")), "{name}: {field} is not assigned as a quoted literal");
            }
            for field in ["CA_URL", "TOKEN", "SSID", "RADIUS_SERVER_NAME"] {
                assert_eq!(
                    template.matches(&format!("{{{{{field}}}}}")).count(),
                    1,
                    "{name}: {field} must appear only in its quoted assignment"
                );
            }
            assert!(template.is_ascii(), "{name} template must be ASCII");
        }
    }
}
