// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use base64::Engine as _;
use std::collections::HashMap;

const PLACEHOLDER_PREFIX: &str = "openshell:resolve:env:";

#[derive(Debug, Clone, Default)]
pub(crate) struct SecretResolver {
    by_placeholder: HashMap<String, String>,
}

impl SecretResolver {
    pub(crate) fn from_provider_env(
        provider_env: HashMap<String, String>,
    ) -> (HashMap<String, String>, Option<Self>) {
        if provider_env.is_empty() {
            return (HashMap::new(), None);
        }

        let mut child_env = HashMap::with_capacity(provider_env.len());
        let mut by_placeholder = HashMap::with_capacity(provider_env.len());

        for (key, value) in provider_env {
            let placeholder = placeholder_for_env_key(&key);
            child_env.insert(key, placeholder.clone());
            by_placeholder.insert(placeholder, value);
        }

        (child_env, Some(Self { by_placeholder }))
    }

    pub(crate) fn resolve_placeholder(&self, value: &str) -> Option<&str> {
        self.by_placeholder.get(value).map(String::as_str)
    }

    pub(crate) fn rewrite_header_value(&self, value: &str) -> Option<String> {
        // Direct placeholder match: `x-api-key: openshell:resolve:env:KEY`
        if let Some(secret) = self.resolve_placeholder(value.trim()) {
            return Some(secret.to_string());
        }

        let trimmed = value.trim();

        // Basic auth decoding: `Basic <base64>` where the decoded content
        // contains a placeholder (e.g. `user:openshell:resolve:env:PASS`).
        // Decode, rewrite placeholders in the decoded string, re-encode.
        if let Some(encoded) = trimmed.strip_prefix("Basic ").map(str::trim) {
            if let Some(rewritten) = self.rewrite_basic_auth_token(encoded) {
                return Some(format!("Basic {rewritten}"));
            }
        }

        // Prefixed placeholder: `Bearer openshell:resolve:env:KEY`
        let split_at = trimmed.find(char::is_whitespace)?;
        let prefix = &trimmed[..split_at];
        let candidate = trimmed[split_at..].trim();
        let secret = self.resolve_placeholder(candidate)?;
        Some(format!("{prefix} {secret}"))
    }

    /// Decode a Base64-encoded Basic auth token, resolve any placeholders in
    /// the decoded `username:password` string, and re-encode.
    ///
    /// Returns `None` if decoding fails or no placeholders are found.
    fn rewrite_basic_auth_token(&self, encoded: &str) -> Option<String> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let decoded_bytes = b64.decode(encoded.trim()).ok()?;
        let decoded = std::str::from_utf8(&decoded_bytes).ok()?;

        // Check if the decoded string contains any placeholder
        if !decoded.contains(PLACEHOLDER_PREFIX) {
            return None;
        }

        // Rewrite all placeholder occurrences in the decoded string
        let mut rewritten = decoded.to_string();
        for (placeholder, secret) in &self.by_placeholder {
            if rewritten.contains(placeholder.as_str()) {
                rewritten = rewritten.replace(placeholder.as_str(), secret);
            }
        }

        // Only return if we actually changed something
        if rewritten == decoded {
            return None;
        }

        Some(b64.encode(rewritten.as_bytes()))
    }
}

pub(crate) fn placeholder_for_env_key(key: &str) -> String {
    format!("{PLACEHOLDER_PREFIX}{key}")
}

pub(crate) fn rewrite_http_header_block(raw: &[u8], resolver: Option<&SecretResolver>) -> Vec<u8> {
    let Some(resolver) = resolver else {
        return raw.to_vec();
    };

    let Some(header_end) = raw.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4) else {
        return raw.to_vec();
    };

    let header_str = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = header_str.split("\r\n");
    let Some(request_line) = lines.next() else {
        return raw.to_vec();
    };

    let mut output = Vec::with_capacity(raw.len());
    output.extend_from_slice(rewrite_request_line(request_line, resolver).as_bytes());
    output.extend_from_slice(b"\r\n");

    for line in lines {
        if line.is_empty() {
            break;
        }

        output.extend_from_slice(rewrite_header_line(line, resolver).as_bytes());
        output.extend_from_slice(b"\r\n");
    }

    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(&raw[header_end..]);
    output
}

pub(crate) fn rewrite_header_line(line: &str, resolver: &SecretResolver) -> String {
    let Some((name, value)) = line.split_once(':') else {
        return line.to_string();
    };

    match resolver.rewrite_header_value(value.trim()) {
        Some(rewritten) => format!("{name}: {rewritten}"),
        None => line.to_string(),
    }
}

/// Rewrite credential placeholders in the request line's URL query parameters.
///
/// Given a request line like `GET /api?key=openshell:resolve:env:API_KEY HTTP/1.1`,
/// resolves placeholders in query parameter values and percent-encodes the
/// resolved secret. Handles URLs with multiple query parameters and preserves
/// parameters that don't contain placeholders.
fn rewrite_request_line(line: &str, resolver: &SecretResolver) -> String {
    // Request line format: METHOD SP REQUEST-URI SP HTTP-VERSION
    let mut parts = line.splitn(3, ' ');
    let method = match parts.next() {
        Some(m) => m,
        None => return line.to_string(),
    };
    let uri = match parts.next() {
        Some(u) => u,
        None => return line.to_string(),
    };
    let version = match parts.next() {
        Some(v) => v,
        None => return line.to_string(),
    };

    // Only rewrite if the URI contains a placeholder
    if !uri.contains(PLACEHOLDER_PREFIX) {
        return line.to_string();
    }

    let rewritten_uri = rewrite_uri_query_params(uri, resolver);
    format!("{method} {rewritten_uri} {version}")
}

/// Rewrite placeholders in query parameter values of a URI.
///
/// Splits the URI at `?`, parses key=value pairs from the query string,
/// resolves any placeholder values, and percent-encodes the resolved secrets.
/// Parameters without placeholders are preserved verbatim.
fn rewrite_uri_query_params(uri: &str, resolver: &SecretResolver) -> String {
    let Some((path, query)) = uri.split_once('?') else {
        return uri.to_string();
    };

    let mut rewritten_params = Vec::new();
    for param in query.split('&') {
        if let Some((key, value)) = param.split_once('=') {
            // Percent-decode the value before checking for placeholder
            let decoded_value = percent_decode(value);
            if let Some(secret) = resolver.resolve_placeholder(&decoded_value) {
                rewritten_params.push(format!("{key}={}", percent_encode(secret)));
            } else {
                rewritten_params.push(param.to_string());
            }
        } else {
            rewritten_params.push(param.to_string());
        }
    }

    format!("{path}?{}", rewritten_params.join("&"))
}

/// Percent-encode a string for safe use in URL query parameter values.
///
/// Encodes all characters except unreserved characters (RFC 3986 Section 2.3):
/// ALPHA / DIGIT / "-" / "." / "_" / "~"
fn percent_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    encoded
}

/// Percent-decode a URL-encoded string.
fn percent_decode(input: &str) -> String {
    let mut decoded = Vec::with_capacity(input.len());
    let mut bytes = input.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hi = bytes.next();
            let lo = bytes.next();
            if let (Some(h), Some(l)) = (hi, lo) {
                let hex = [h, l];
                if let Ok(s) = std::str::from_utf8(&hex) {
                    if let Ok(val) = u8::from_str_radix(s, 16) {
                        decoded.push(val);
                        continue;
                    }
                }
                // Invalid percent encoding — preserve verbatim
                decoded.push(b'%');
                decoded.push(h);
                decoded.push(l);
            } else {
                decoded.push(b'%');
                if let Some(h) = hi {
                    decoded.push(h);
                }
            }
        } else {
            decoded.push(b);
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_env_is_replaced_with_placeholders() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("ANTHROPIC_API_KEY".to_string(), "sk-test".to_string())]
                .into_iter()
                .collect(),
        );

        assert_eq!(
            child_env.get("ANTHROPIC_API_KEY"),
            Some(&"openshell:resolve:env:ANTHROPIC_API_KEY".to_string())
        );
        assert_eq!(
            resolver
                .as_ref()
                .and_then(|resolver| resolver
                    .resolve_placeholder("openshell:resolve:env:ANTHROPIC_API_KEY")),
            Some("sk-test")
        );
    }

    #[test]
    fn rewrites_exact_placeholder_header_values() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("CUSTOM_TOKEN".to_string(), "secret-token".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");

        assert_eq!(
            rewrite_header_line("x-api-key: openshell:resolve:env:CUSTOM_TOKEN", &resolver),
            "x-api-key: secret-token"
        );
    }

    #[test]
    fn rewrites_bearer_placeholder_header_values() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("ANTHROPIC_API_KEY".to_string(), "sk-test".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");

        assert_eq!(
            rewrite_header_line(
                "Authorization: Bearer openshell:resolve:env:ANTHROPIC_API_KEY",
                &resolver,
            ),
            "Authorization: Bearer sk-test"
        );
    }

    #[test]
    fn rewrites_http_header_blocks_and_preserves_body() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("CUSTOM_TOKEN".to_string(), "secret-token".to_string())]
                .into_iter()
                .collect(),
        );

        let raw = b"POST /v1 HTTP/1.1\r\nAuthorization: Bearer openshell:resolve:env:CUSTOM_TOKEN\r\nContent-Length: 5\r\n\r\nhello";
        let rewritten = rewrite_http_header_block(raw, resolver.as_ref());
        let rewritten = String::from_utf8(rewritten).expect("utf8");

        assert!(rewritten.contains("Authorization: Bearer secret-token\r\n"));
        assert!(rewritten.ends_with("\r\n\r\nhello"));
    }

    /// Simulates the full round-trip: provider env → child placeholders →
    /// HTTP headers → rewrite. This is the exact flow that occurs when a
    /// sandbox child process reads placeholder env vars, constructs an HTTP
    /// request, and the proxy rewrites headers before forwarding upstream.
    #[test]
    fn full_round_trip_child_env_to_rewritten_headers() {
        let provider_env: HashMap<String, String> = [
            (
                "ANTHROPIC_API_KEY".to_string(),
                "sk-real-key-12345".to_string(),
            ),
            (
                "CUSTOM_SERVICE_TOKEN".to_string(),
                "tok-real-svc-67890".to_string(),
            ),
        ]
        .into_iter()
        .collect();

        let (child_env, resolver) = SecretResolver::from_provider_env(provider_env);

        // Child process reads placeholders from the environment
        let auth_value = child_env.get("ANTHROPIC_API_KEY").unwrap();
        let token_value = child_env.get("CUSTOM_SERVICE_TOKEN").unwrap();
        assert!(auth_value.starts_with(PLACEHOLDER_PREFIX));
        assert!(token_value.starts_with(PLACEHOLDER_PREFIX));

        // Child constructs an HTTP request using those placeholders
        let raw = format!(
            "GET /v1/messages HTTP/1.1\r\n\
             Host: api.example.com\r\n\
             Authorization: Bearer {auth_value}\r\n\
             x-api-key: {token_value}\r\n\
             Content-Length: 0\r\n\r\n"
        );

        // Proxy rewrites headers
        let rewritten = rewrite_http_header_block(raw.as_bytes(), resolver.as_ref());
        let rewritten = String::from_utf8(rewritten).expect("utf8");

        // Real secrets must appear in the rewritten headers
        assert!(
            rewritten.contains("Authorization: Bearer sk-real-key-12345\r\n"),
            "Expected rewritten Authorization header, got: {rewritten}"
        );
        assert!(
            rewritten.contains("x-api-key: tok-real-svc-67890\r\n"),
            "Expected rewritten x-api-key header, got: {rewritten}"
        );

        // Placeholders must not appear
        assert!(
            !rewritten.contains("openshell:resolve:env:"),
            "Placeholder leaked into rewritten request: {rewritten}"
        );

        // Request line and non-secret headers must be preserved
        assert!(rewritten.starts_with("GET /v1/messages HTTP/1.1\r\n"));
        assert!(rewritten.contains("Host: api.example.com\r\n"));
        assert!(rewritten.contains("Content-Length: 0\r\n"));
    }

    #[test]
    fn non_secret_headers_are_not_modified() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("API_KEY".to_string(), "secret".to_string())]
                .into_iter()
                .collect(),
        );

        let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: application/json\r\nContent-Type: text/plain\r\n\r\n";
        let rewritten = rewrite_http_header_block(raw, resolver.as_ref());
        // The output should be byte-identical since no placeholders are present
        assert_eq!(raw.as_slice(), rewritten.as_slice());
    }

    #[test]
    fn empty_provider_env_produces_no_resolver() {
        let (child_env, resolver) = SecretResolver::from_provider_env(HashMap::new());
        assert!(child_env.is_empty());
        assert!(resolver.is_none());
    }

    #[test]
    fn rewrite_with_no_resolver_returns_original() {
        let raw = b"GET / HTTP/1.1\r\nAuthorization: Bearer my-token\r\n\r\n";
        let rewritten = rewrite_http_header_block(raw, None);
        assert_eq!(raw.as_slice(), rewritten.as_slice());
    }

    // --- Query parameter rewriting tests ---

    #[test]
    fn rewrites_query_param_placeholder_in_request_line() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("YOUTUBE_API_KEY".to_string(), "AIzaSy-secret".to_string())]
                .into_iter()
                .collect(),
        );
        let placeholder = child_env.get("YOUTUBE_API_KEY").unwrap();

        let raw = format!(
            "GET /youtube/v3/search?part=snippet&key={placeholder} HTTP/1.1\r\n\
             Host: www.googleapis.com\r\n\r\n"
        );
        let rewritten = rewrite_http_header_block(raw.as_bytes(), resolver.as_ref());
        let rewritten = String::from_utf8(rewritten).expect("utf8");

        assert!(
            rewritten.starts_with("GET /youtube/v3/search?part=snippet&key=AIzaSy-secret HTTP/1.1\r\n"),
            "Expected query param rewritten, got: {rewritten}"
        );
        assert!(!rewritten.contains("openshell:resolve:env:"));
    }

    #[test]
    fn rewrites_query_param_with_special_chars_percent_encoded() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("API_KEY".to_string(), "key with spaces&symbols=yes".to_string())]
                .into_iter()
                .collect(),
        );
        let placeholder = child_env.get("API_KEY").unwrap();

        let raw = format!(
            "GET /api?token={placeholder} HTTP/1.1\r\nHost: x\r\n\r\n"
        );
        let rewritten = rewrite_http_header_block(raw.as_bytes(), resolver.as_ref());
        let rewritten = String::from_utf8(rewritten).expect("utf8");

        // Secret should be percent-encoded
        assert!(
            rewritten.contains("token=key%20with%20spaces%26symbols%3Dyes"),
            "Expected percent-encoded secret, got: {rewritten}"
        );
    }

    #[test]
    fn rewrites_query_param_only_placeholder_first_param() {
        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("KEY".to_string(), "secret123".to_string())]
                .into_iter()
                .collect(),
        );
        let placeholder = child_env.get("KEY").unwrap();

        let raw = format!(
            "GET /api?key={placeholder}&format=json HTTP/1.1\r\nHost: x\r\n\r\n"
        );
        let rewritten = rewrite_http_header_block(raw.as_bytes(), resolver.as_ref());
        let rewritten = String::from_utf8(rewritten).expect("utf8");

        assert!(
            rewritten.starts_with("GET /api?key=secret123&format=json HTTP/1.1"),
            "Expected first param rewritten, got: {rewritten}"
        );
    }

    #[test]
    fn no_query_param_rewrite_without_placeholder() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("KEY".to_string(), "secret".to_string())]
                .into_iter()
                .collect(),
        );

        let raw = b"GET /api?key=normalvalue HTTP/1.1\r\nHost: x\r\n\r\n";
        let rewritten = rewrite_http_header_block(raw, resolver.as_ref());
        assert_eq!(raw.as_slice(), rewritten.as_slice());
    }

    // --- Basic Authorization header encoding tests ---

    #[test]
    fn rewrites_basic_auth_placeholder_in_decoded_token() {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;

        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("DB_PASSWORD".to_string(), "s3cret!".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");
        let placeholder = child_env.get("DB_PASSWORD").unwrap();

        // Simulate: agent constructs Basic auth with placeholder password
        let credentials = format!("admin:{placeholder}");
        let encoded = b64.encode(credentials.as_bytes());

        let header_line = format!("Authorization: Basic {encoded}");
        let rewritten = rewrite_header_line(&header_line, &resolver);

        // Decode the rewritten token to verify
        let rewritten_token = rewritten.strip_prefix("Authorization: Basic ").unwrap();
        let decoded = b64.decode(rewritten_token).unwrap();
        let decoded_str = std::str::from_utf8(&decoded).unwrap();

        assert_eq!(decoded_str, "admin:s3cret!");
        assert!(!rewritten.contains("openshell:resolve:env:"));
    }

    #[test]
    fn basic_auth_without_placeholder_unchanged() {
        let (_, resolver) = SecretResolver::from_provider_env(
            [("KEY".to_string(), "secret".to_string())]
                .into_iter()
                .collect(),
        );
        let resolver = resolver.expect("resolver");

        // Normal Basic auth token without any placeholder
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let encoded = b64.encode(b"user:password");
        let header_line = format!("Authorization: Basic {encoded}");

        let rewritten = rewrite_header_line(&header_line, &resolver);
        assert_eq!(rewritten, header_line, "Should not modify non-placeholder Basic auth");
    }

    #[test]
    fn basic_auth_full_round_trip_header_block() {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;

        let (child_env, resolver) = SecretResolver::from_provider_env(
            [("REGISTRY_PASS".to_string(), "hunter2".to_string())]
                .into_iter()
                .collect(),
        );
        let placeholder = child_env.get("REGISTRY_PASS").unwrap();
        let credentials = format!("deploy:{placeholder}");
        let encoded = b64.encode(credentials.as_bytes());

        let raw = format!(
            "GET /v2/_catalog HTTP/1.1\r\n\
             Host: registry.example.com\r\n\
             Authorization: Basic {encoded}\r\n\
             Accept: application/json\r\n\r\n"
        );

        let rewritten = rewrite_http_header_block(raw.as_bytes(), resolver.as_ref());
        let rewritten = String::from_utf8(rewritten).expect("utf8");

        // Extract and decode the rewritten Basic token
        let auth_line = rewritten.lines().find(|l| l.starts_with("Authorization:")).unwrap();
        let token = auth_line.strip_prefix("Authorization: Basic ").unwrap();
        let decoded = b64.decode(token).unwrap();
        assert_eq!(std::str::from_utf8(&decoded).unwrap(), "deploy:hunter2");

        // Other headers preserved
        assert!(rewritten.contains("Host: registry.example.com\r\n"));
        assert!(rewritten.contains("Accept: application/json\r\n"));
        assert!(!rewritten.contains("openshell:resolve:env:"));
    }

    // --- Percent encoding tests ---

    #[test]
    fn percent_encode_preserves_unreserved() {
        assert_eq!(percent_encode("abc123-._~"), "abc123-._~");
    }

    #[test]
    fn percent_encode_encodes_special_chars() {
        assert_eq!(percent_encode("a b"), "a%20b");
        assert_eq!(percent_encode("key=val&x"), "key%3Dval%26x");
    }

    #[test]
    fn percent_decode_round_trips() {
        let original = "hello world & more=stuff";
        let encoded = percent_encode(original);
        let decoded = percent_decode(&encoded);
        assert_eq!(decoded, original);
    }
}
