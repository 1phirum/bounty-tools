//! Endpoint classification: turn a path into an [`EndpointKind`].
//!
//! Classification is deliberately conservative and cheap — it reads only the
//! path/extension, never fetches anything, and prefers `Page` when unsure so
//! a real API route is never *downgraded* to a static asset by accident.

use crate::models::EndpointKind;

/// File extensions that mark a reference as a static asset.
const ASSET_EXTENSIONS: &[&str] = &[
    "js", "mjs", "cjs", "css", "map", "png", "jpg", "jpeg", "gif", "svg", "webp",
    "ico", "bmp", "woff", "woff2", "ttf", "eot", "otf", "mp4", "webm", "mp3",
    "wav", "pdf", "zip", "gz", "wasm",
];

/// Substrings that strongly indicate an application/API route.
const API_MARKERS: &[&str] = &[
    "/api/", "/api.", "/graphql", "/gql", "/rest/", "/rpc", "/jsonrpc",
    "/v1/", "/v2/", "/v3/", "/oauth", "/oauth2", "/token", "/.json",
    "/wp-json/", "/rest_route",
];

/// Classify a *path* (no scheme/host). `is_form` forces a form-action verdict
/// unless the action is clearly an API route, in which case that wins.
pub fn classify(path: &str, is_form: bool) -> EndpointKind {
    let full = path.to_ascii_lowercase();

    if full.starts_with("ws://") || full.starts_with("wss://") {
        return EndpointKind::WebSocket;
    }

    // Everything below reads the path only, never the query/fragment, so a
    // value like `?file=app.js` cannot masquerade as an asset or API route.
    let lower = full
        .split(['?', '#'])
        .next()
        .unwrap_or(&full)
        .to_string();
    let lower = lower.as_str();

    let looks_api = API_MARKERS.iter().any(|m| lower.contains(m)) || lower.ends_with(".json");

    if looks_api {
        return EndpointKind::ApiRoute;
    }

    if is_form {
        return EndpointKind::FormAction;
    }

    if let Some(ext) = extension(&lower) {
        if ASSET_EXTENSIONS.contains(&ext) {
            return EndpointKind::StaticAsset;
        }
    }

    EndpointKind::Page
}

/// The lowercase extension of the last path segment, if any, ignoring a query
/// string. Returns `None` when the last segment has no `.`.
fn extension(path: &str) -> Option<&str> {
    let path = path.split(['?', '#']).next().unwrap_or(path);
    let last = path.rsplit('/').next().unwrap_or(path);
    last.rsplit_once('.').map(|(_, ext)| ext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_markers_win_over_form_and_extension() {
        assert_eq!(classify("/api/v1/users", false), EndpointKind::ApiRoute);
        assert_eq!(classify("/api/login", true), EndpointKind::ApiRoute);
        assert_eq!(classify("/graphql", false), EndpointKind::ApiRoute);
        assert_eq!(classify("/data/report.json", false), EndpointKind::ApiRoute);
    }

    #[test]
    fn assets_by_extension() {
        assert_eq!(classify("/static/app.js", false), EndpointKind::StaticAsset);
        assert_eq!(classify("/img/logo.png", false), EndpointKind::StaticAsset);
        assert_eq!(classify("/app.4f3a.css", false), EndpointKind::StaticAsset);
    }

    #[test]
    fn forms_and_pages() {
        assert_eq!(classify("/search", true), EndpointKind::FormAction);
        assert_eq!(classify("/about", false), EndpointKind::Page);
        assert_eq!(classify("/user/profile", false), EndpointKind::Page);
    }

    #[test]
    fn websockets() {
        assert_eq!(classify("wss://host/live", false), EndpointKind::WebSocket);
    }

    #[test]
    fn query_string_does_not_confuse_extension() {
        // `.js` in a query value must not make this an asset.
        assert_eq!(classify("/search?file=app.js", false), EndpointKind::Page);
    }
}
