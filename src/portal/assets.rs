//! Static files embedded in the binary.

use crate::shared::http::{self, Reply};

const STYLE: &str = include_str!("assets/style.css");
const SCRIPT: &str = include_str!("assets/app.js");
const BACKGROUND: &str = include_str!("assets/background.svg");
const FAVICON: &str = include_str!("assets/favicon.svg");
const FONT_REGULAR: &[u8] = include_bytes!("assets/fonts/IBMPlexMono-Regular.woff2");
const FONT_SEMIBOLD: &[u8] = include_bytes!("assets/fonts/IBMPlexMono-SemiBold.woff2");

/// Returns the asset at `path`, if there is one.
pub fn get(path: &str) -> Option<Reply> {
    let (content_type, body): (&str, Vec<u8>) = match path {
        "/style.css" => ("text/css; charset=utf-8", STYLE.into()),
        "/app.js" => ("text/javascript; charset=utf-8", SCRIPT.into()),
        "/background-light.svg" => ("image/svg+xml", background("#1e272c", "0.55").into()),
        "/background-dark.svg" => ("image/svg+xml", background("#c9c4b8", "0.22").into()),
        "/favicon.svg" => ("image/svg+xml", FAVICON.into()),
        "/fonts/plex-mono-400.woff2" => ("font/woff2", FONT_REGULAR.into()),
        "/fonts/plex-mono-600.woff2" => ("font/woff2", FONT_SEMIBOLD.into()),
        _ => return None,
    };
    Some(http::asset(content_type, &body))
}

/// The halftone background in the dot colour for a theme.
fn background(dot: &str, opacity: &str) -> String {
    BACKGROUND.replace("{{dot}}", dot).replace("{{opacity}}", opacity)
}
