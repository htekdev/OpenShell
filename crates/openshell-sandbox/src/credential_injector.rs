// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! L7 proxy credential injection for non-inference providers.
//!
//! When a network policy endpoint has a `credential_injection` configuration,
//! the referenced provider credential is **not** injected as an environment
//! variable into the sandbox. Instead, the L7 proxy injects it into outbound
//! HTTP requests at the network layer — the agent process never sees the raw
//! API key.
//!
//! Supports three injection styles:
//! - **Header**: sets an HTTP header (e.g., `x-api-key: <value>`)
//! - **Header with prefix**: sets a header with a prefix (e.g., `Authorization: Bearer <value>`)
//! - **Query parameter**: appends a URL query parameter (e.g., `?key=<value>`)

use std::collections::HashMap;

use openshell_core::proto::SandboxPolicy;
use tracing::{debug, warn};

/// How to inject the credential into the outbound HTTP request.
#[derive(Debug, Clone)]
pub(crate) enum InjectionTarget {
    /// Set an HTTP header. If `value_prefix` is non-empty, the header value
    /// is `{prefix}{credential}` (e.g., `Bearer sk-xxx`).
    Header {
        name: String,
        value_prefix: String,
    },
    /// Append a URL query parameter.
    QueryParam {
        name: String,
    },
}

/// A fully resolved credential injection — target + actual secret value.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedInjection {
    pub target: InjectionTarget,
    pub value: String,
}

/// Maps network endpoints to their credential injection configurations.
///
/// Built at sandbox startup by cross-referencing policy `credential_injection`
/// entries with the provider credential environment. Passed to the L7 proxy
/// for runtime injection.
#[derive(Debug, Clone, Default)]
pub(crate) struct CredentialInjector {
    /// Entries keyed by `(host_pattern, port)`. Host patterns may contain
    /// glob wildcards (e.g., `*.example.com`).
    entries: Vec<InjectionEntry>,
}

#[derive(Debug, Clone)]
struct InjectionEntry {
    host: String,
    ports: Vec<u32>,
    injection: ResolvedInjection,
}

impl CredentialInjector {
    /// Scan a sandbox policy for `credential_injection` configs and resolve
    /// them against the provider environment.
    ///
    /// Returns `(injector, filtered_env)`:
    /// - `injector` contains all resolved credential injections for the proxy.
    /// - `filtered_env` has the injected credentials **removed** so they won't
    ///   be exposed as environment variables in the sandbox.
    pub(crate) fn extract_from_policy(
        policy: &SandboxPolicy,
        mut provider_env: HashMap<String, String>,
    ) -> (Self, HashMap<String, String>) {
        let mut entries = Vec::new();
        let mut used_credentials = std::collections::HashSet::new();

        for (policy_name, rule) in &policy.network_policies {
            for (i, endpoint) in rule.endpoints.iter().enumerate() {
                let Some(ci) = &endpoint.credential_injection else {
                    continue;
                };

                if ci.credential.is_empty() {
                    warn!(
                        policy = %policy_name,
                        endpoint = i,
                        "credential_injection has empty credential key, skipping"
                    );
                    continue;
                }

                let Some(secret_value) = provider_env.get(&ci.credential).cloned() else {
                    warn!(
                        policy = %policy_name,
                        endpoint = i,
                        credential = %ci.credential,
                        provider = %ci.provider,
                        "credential_injection references credential not found in provider environment, skipping"
                    );
                    continue;
                };

                let target = if !ci.header.is_empty() {
                    InjectionTarget::Header {
                        name: ci.header.clone(),
                        value_prefix: ci.value_prefix.clone(),
                    }
                } else if !ci.query_param.is_empty() {
                    InjectionTarget::QueryParam {
                        name: ci.query_param.clone(),
                    }
                } else {
                    warn!(
                        policy = %policy_name,
                        endpoint = i,
                        "credential_injection has neither header nor query_param, skipping"
                    );
                    continue;
                };

                let ports = if endpoint.ports.is_empty() && endpoint.port > 0 {
                    vec![endpoint.port]
                } else {
                    endpoint.ports.clone()
                };

                debug!(
                    policy = %policy_name,
                    endpoint = i,
                    host = %endpoint.host,
                    credential = %ci.credential,
                    "credential injection configured"
                );

                used_credentials.insert(ci.credential.clone());

                entries.push(InjectionEntry {
                    host: endpoint.host.clone(),
                    ports,
                    injection: ResolvedInjection {
                        target,
                        value: secret_value,
                    },
                });
            }
        }

        // Remove used credentials from provider env after the loop so
        // multiple endpoints can share the same credential.
        for key in &used_credentials {
            provider_env.remove(key);
        }

        (Self { entries }, provider_env)
    }

    /// Look up the credential injection for a given host and port.
    ///
    /// Returns `None` if no injection is configured for this endpoint.
    /// Supports exact host match (case-insensitive) and glob patterns
    /// using `.` as delimiter (matching the OPA policy behavior).
    pub(crate) fn lookup(&self, host: &str, port: u16) -> Option<&ResolvedInjection> {
        let host_lower = host.to_ascii_lowercase();
        let port_u32 = u32::from(port);

        self.entries.iter().find_map(|entry| {
            if !entry.ports.contains(&port_u32) {
                return None;
            }

            let entry_host = entry.host.to_ascii_lowercase();
            if entry_host == host_lower {
                return Some(&entry.injection);
            }

            if entry_host.contains('*') && glob_match_host(&entry_host, &host_lower) {
                return Some(&entry.injection);
            }

            None
        })
    }

    /// Returns `true` if no credential injections are configured.
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of configured credential injections.
    pub(crate) fn entries_count(&self) -> usize {
        self.entries.len()
    }
}

/// Apply credential injection to a raw HTTP request.
///
/// For header injection: strips any existing header with the same name and
/// appends the injected header. For query parameter injection: appends the
/// parameter to the request URL.
///
/// Returns the modified request bytes.
pub(crate) fn inject_credential(raw: &[u8], injection: &ResolvedInjection) -> Vec<u8> {
    match &injection.target {
        InjectionTarget::Header { name, value_prefix } => {
            inject_header(raw, name, value_prefix, &injection.value)
        }
        InjectionTarget::QueryParam { name } => {
            inject_query_param(raw, name, &injection.value)
        }
    }
}

/// Inject a credential as an HTTP header.
///
/// 1. Strip any existing header with the same name (case-insensitive).
/// 2. Append the new header before the final `\r\n\r\n`.
fn inject_header(raw: &[u8], header_name: &str, value_prefix: &str, value: &str) -> Vec<u8> {
    let Some(header_end) = raw.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4) else {
        return raw.to_vec();
    };

    let header_str = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = header_str.split("\r\n");
    let Some(request_line) = lines.next() else {
        return raw.to_vec();
    };

    let header_name_lower = header_name.to_ascii_lowercase();

    let mut output = Vec::with_capacity(raw.len() + header_name.len() + value_prefix.len() + value.len() + 6);
    output.extend_from_slice(request_line.as_bytes());
    output.extend_from_slice(b"\r\n");

    // Copy headers, stripping any existing header with the same name
    for line in lines {
        if line.is_empty() {
            break;
        }

        if let Some((name, _)) = line.split_once(':') {
            if name.trim().to_ascii_lowercase() == header_name_lower {
                continue; // Strip existing header
            }
        }

        output.extend_from_slice(line.as_bytes());
        output.extend_from_slice(b"\r\n");
    }

    // Append injected header
    output.extend_from_slice(header_name.as_bytes());
    output.extend_from_slice(b": ");
    output.extend_from_slice(value_prefix.as_bytes());
    output.extend_from_slice(value.as_bytes());
    output.extend_from_slice(b"\r\n");

    // End of headers
    output.extend_from_slice(b"\r\n");

    // Append body
    output.extend_from_slice(&raw[header_end..]);

    output
}

/// Inject a credential as a URL query parameter.
///
/// Modifies the request line to append `?name=value` or `&name=value`.
fn inject_query_param(raw: &[u8], param_name: &str, value: &str) -> Vec<u8> {
    let Some(header_end) = raw.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4) else {
        return raw.to_vec();
    };

    let header_str = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = header_str.split("\r\n");
    let Some(request_line) = lines.next() else {
        return raw.to_vec();
    };

    // Parse request line: METHOD URI HTTP/VERSION
    let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
    if parts.len() != 3 {
        return raw.to_vec();
    }
    let method = parts[0];
    let uri = parts[1];
    let version = parts[2];

    // URL-encode the value (minimal: encode &, =, ?, #, space, and non-ASCII)
    let encoded_value = url_encode_param(value);

    let separator = if uri.contains('?') { "&" } else { "?" };
    let new_uri = format!("{uri}{separator}{param_name}={encoded_value}");

    let new_request_line = format!("{method} {new_uri} {version}");

    let mut output = Vec::with_capacity(raw.len() + param_name.len() + encoded_value.len() + 2);
    output.extend_from_slice(new_request_line.as_bytes());
    output.extend_from_slice(b"\r\n");

    // Copy remaining headers
    for line in lines {
        if line.is_empty() {
            break;
        }
        output.extend_from_slice(line.as_bytes());
        output.extend_from_slice(b"\r\n");
    }

    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(&raw[header_end..]);

    output
}

/// Minimal URL percent-encoding for query parameter values.
fn url_encode_param(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    encoded
}

/// Glob match a hostname pattern against a target hostname.
///
/// Uses `.` as the delimiter (matching OPA policy behavior):
/// - `*.example.com` matches `api.example.com` but not `sub.api.example.com`
/// - `**.example.com` matches `api.example.com` and `sub.api.example.com`
fn glob_match_host(pattern: &str, target: &str) -> bool {
    if pattern.starts_with("**.") {
        let suffix = &pattern[3..];
        target.ends_with(suffix)
            && target.len() > suffix.len()
            && target.as_bytes()[target.len() - suffix.len() - 1] == b'.'
    } else if pattern.starts_with("*.") {
        let suffix = &pattern[2..];
        if !target.ends_with(suffix) {
            return false;
        }
        let prefix = &target[..target.len() - suffix.len()];
        // Single label: no dots allowed in the matched prefix
        !prefix.is_empty() && prefix.ends_with('.') && !prefix[..prefix.len() - 1].contains('.')
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{
        CredentialInjection, NetworkEndpoint, NetworkPolicyRule, SandboxPolicy,
    };

    fn make_policy_with_injection(
        host: &str,
        port: u32,
        ci: CredentialInjection,
    ) -> SandboxPolicy {
        let mut network_policies = std::collections::BTreeMap::new();
        network_policies.insert(
            "test_api".to_string(),
            NetworkPolicyRule {
                name: "test-api".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: host.to_string(),
                    port,
                    ports: vec![port],
                    credential_injection: Some(ci),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        SandboxPolicy {
            network_policies,
            ..Default::default()
        }
    }

    #[test]
    fn extract_header_injection() {
        let policy = make_policy_with_injection(
            "api.exa.ai",
            443,
            CredentialInjection {
                header: "x-api-key".to_string(),
                provider: "exa".to_string(),
                credential: "EXA_API_KEY".to_string(),
                ..Default::default()
            },
        );
        let provider_env: HashMap<String, String> = [
            ("EXA_API_KEY".to_string(), "test-key-123".to_string()),
            ("OTHER_KEY".to_string(), "other-value".to_string()),
        ]
        .into_iter()
        .collect();

        let (injector, filtered_env) =
            CredentialInjector::extract_from_policy(&policy, provider_env);

        // Injected credential should be removed from env
        assert!(!filtered_env.contains_key("EXA_API_KEY"));
        // Other credentials should remain
        assert_eq!(filtered_env.get("OTHER_KEY").unwrap(), "other-value");
        // Injector should have the entry
        assert!(!injector.is_empty());
        let injection = injector.lookup("api.exa.ai", 443).unwrap();
        assert!(matches!(&injection.target, InjectionTarget::Header { name, .. } if name == "x-api-key"));
        assert_eq!(injection.value, "test-key-123");
    }

    #[test]
    fn extract_header_with_prefix() {
        let policy = make_policy_with_injection(
            "api.perplexity.ai",
            443,
            CredentialInjection {
                header: "Authorization".to_string(),
                value_prefix: "Bearer ".to_string(),
                provider: "perplexity".to_string(),
                credential: "PERPLEXITY_API_KEY".to_string(),
                ..Default::default()
            },
        );
        let provider_env: HashMap<String, String> =
            [("PERPLEXITY_API_KEY".to_string(), "pplx-xxx".to_string())]
                .into_iter()
                .collect();

        let (injector, filtered_env) =
            CredentialInjector::extract_from_policy(&policy, provider_env);

        assert!(filtered_env.is_empty());
        let injection = injector.lookup("api.perplexity.ai", 443).unwrap();
        match &injection.target {
            InjectionTarget::Header { name, value_prefix } => {
                assert_eq!(name, "Authorization");
                assert_eq!(value_prefix, "Bearer ");
            }
            _ => panic!("expected header injection"),
        }
        assert_eq!(injection.value, "pplx-xxx");
    }

    #[test]
    fn extract_query_param_injection() {
        let policy = make_policy_with_injection(
            "www.googleapis.com",
            443,
            CredentialInjection {
                query_param: "key".to_string(),
                provider: "youtube".to_string(),
                credential: "YOUTUBE_API_KEY".to_string(),
                ..Default::default()
            },
        );
        let provider_env: HashMap<String, String> =
            [("YOUTUBE_API_KEY".to_string(), "AIza-test".to_string())]
                .into_iter()
                .collect();

        let (injector, filtered_env) =
            CredentialInjector::extract_from_policy(&policy, provider_env);

        assert!(filtered_env.is_empty());
        let injection = injector.lookup("www.googleapis.com", 443).unwrap();
        assert!(matches!(&injection.target, InjectionTarget::QueryParam { name } if name == "key"));
        assert_eq!(injection.value, "AIza-test");
    }

    #[test]
    fn missing_credential_skips_and_preserves_env() {
        let policy = make_policy_with_injection(
            "api.example.com",
            443,
            CredentialInjection {
                header: "x-api-key".to_string(),
                provider: "example".to_string(),
                credential: "MISSING_KEY".to_string(),
                ..Default::default()
            },
        );
        let provider_env: HashMap<String, String> =
            [("OTHER_KEY".to_string(), "value".to_string())]
                .into_iter()
                .collect();

        let (injector, filtered_env) =
            CredentialInjector::extract_from_policy(&policy, provider_env);

        assert!(injector.is_empty());
        assert_eq!(filtered_env.get("OTHER_KEY").unwrap(), "value");
    }

    #[test]
    fn shared_credential_across_endpoints() {
        let mut network_policies = std::collections::BTreeMap::new();
        network_policies.insert(
            "exa_api".to_string(),
            NetworkPolicyRule {
                name: "exa-api".to_string(),
                endpoints: vec![
                    NetworkEndpoint {
                        host: "api.exa.ai".to_string(),
                        port: 443,
                        ports: vec![443],
                        credential_injection: Some(CredentialInjection {
                            header: "x-api-key".to_string(),
                            provider: "exa".to_string(),
                            credential: "EXA_API_KEY".to_string(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    NetworkEndpoint {
                        host: "backup.exa.ai".to_string(),
                        port: 443,
                        ports: vec![443],
                        credential_injection: Some(CredentialInjection {
                            header: "x-api-key".to_string(),
                            provider: "exa".to_string(),
                            credential: "EXA_API_KEY".to_string(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
        );
        let policy = SandboxPolicy {
            network_policies,
            ..Default::default()
        };
        let provider_env: HashMap<String, String> =
            [("EXA_API_KEY".to_string(), "shared-key".to_string())]
                .into_iter()
                .collect();

        let (injector, filtered_env) =
            CredentialInjector::extract_from_policy(&policy, provider_env);

        // Both endpoints should have injections
        assert!(
            injector.lookup("api.exa.ai", 443).is_some(),
            "primary endpoint should have injection"
        );
        assert!(
            injector.lookup("backup.exa.ai", 443).is_some(),
            "backup endpoint should also have injection (shared credential)"
        );
        // Credential should be removed from env
        assert!(
            !filtered_env.contains_key("EXA_API_KEY"),
            "shared credential should be removed from env"
        );
    }

    #[test]
    fn lookup_case_insensitive() {
        let policy = make_policy_with_injection(
            "API.Exa.AI",
            443,
            CredentialInjection {
                header: "x-api-key".to_string(),
                provider: "exa".to_string(),
                credential: "KEY".to_string(),
                ..Default::default()
            },
        );
        let provider_env = [("KEY".to_string(), "val".to_string())]
            .into_iter()
            .collect();

        let (injector, _) = CredentialInjector::extract_from_policy(&policy, provider_env);

        assert!(injector.lookup("api.exa.ai", 443).is_some());
        assert!(injector.lookup("API.EXA.AI", 443).is_some());
        assert!(injector.lookup("api.exa.ai", 80).is_none());
    }

    #[test]
    fn lookup_glob_single_label() {
        let policy = make_policy_with_injection(
            "*.example.com",
            443,
            CredentialInjection {
                header: "x-api-key".to_string(),
                provider: "example".to_string(),
                credential: "KEY".to_string(),
                ..Default::default()
            },
        );
        let provider_env = [("KEY".to_string(), "val".to_string())]
            .into_iter()
            .collect();

        let (injector, _) = CredentialInjector::extract_from_policy(&policy, provider_env);

        assert!(injector.lookup("api.example.com", 443).is_some());
        assert!(
            injector.lookup("sub.api.example.com", 443).is_none(),
            "*.example.com should not match multiple subdomain labels"
        );
        assert!(injector.lookup("example.com", 443).is_none());
    }

    #[test]
    fn lookup_glob_multi_label() {
        let policy = make_policy_with_injection(
            "**.example.com",
            443,
            CredentialInjection {
                header: "x-api-key".to_string(),
                provider: "example".to_string(),
                credential: "KEY".to_string(),
                ..Default::default()
            },
        );
        let provider_env = [("KEY".to_string(), "val".to_string())]
            .into_iter()
            .collect();

        let (injector, _) = CredentialInjector::extract_from_policy(&policy, provider_env);

        assert!(injector.lookup("api.example.com", 443).is_some());
        assert!(
            injector.lookup("sub.api.example.com", 443).is_some(),
            "**.example.com should match multiple subdomain labels"
        );
        assert!(injector.lookup("example.com", 443).is_none());
    }

    #[test]
    fn inject_header_plain() {
        let raw = b"GET /search HTTP/1.1\r\nHost: api.exa.ai\r\nContent-Length: 0\r\n\r\n";
        let injection = ResolvedInjection {
            target: InjectionTarget::Header {
                name: "x-api-key".to_string(),
                value_prefix: String::new(),
            },
            value: "test-key".to_string(),
        };

        let result = inject_credential(raw, &injection);
        let result_str = String::from_utf8(result).unwrap();

        assert!(result_str.contains("x-api-key: test-key\r\n"));
        assert!(result_str.contains("Host: api.exa.ai\r\n"));
        assert!(result_str.starts_with("GET /search HTTP/1.1\r\n"));
    }

    #[test]
    fn inject_header_with_prefix() {
        let raw = b"POST /chat/completions HTTP/1.1\r\nHost: api.perplexity.ai\r\n\r\n";
        let injection = ResolvedInjection {
            target: InjectionTarget::Header {
                name: "Authorization".to_string(),
                value_prefix: "Bearer ".to_string(),
            },
            value: "pplx-xxx".to_string(),
        };

        let result = inject_credential(raw, &injection);
        let result_str = String::from_utf8(result).unwrap();

        assert!(result_str.contains("Authorization: Bearer pplx-xxx\r\n"));
    }

    #[test]
    fn inject_header_strips_existing() {
        let raw =
            b"GET /search HTTP/1.1\r\nHost: api.exa.ai\r\nx-api-key: agent-fake-key\r\n\r\n";
        let injection = ResolvedInjection {
            target: InjectionTarget::Header {
                name: "x-api-key".to_string(),
                value_prefix: String::new(),
            },
            value: "real-key".to_string(),
        };

        let result = inject_credential(raw, &injection);
        let result_str = String::from_utf8(result).unwrap();

        assert!(
            result_str.contains("x-api-key: real-key\r\n"),
            "should contain injected header"
        );
        assert!(
            !result_str.contains("agent-fake-key"),
            "should strip agent's fake header"
        );
        // Verify only one x-api-key header
        assert_eq!(
            result_str.matches("x-api-key").count(),
            1,
            "should have exactly one x-api-key header"
        );
    }

    #[test]
    fn inject_header_strips_case_insensitive() {
        let raw =
            b"GET /search HTTP/1.1\r\nHost: api.exa.ai\r\nX-Api-Key: agent-fake-key\r\n\r\n";
        let injection = ResolvedInjection {
            target: InjectionTarget::Header {
                name: "x-api-key".to_string(),
                value_prefix: String::new(),
            },
            value: "real-key".to_string(),
        };

        let result = inject_credential(raw, &injection);
        let result_str = String::from_utf8(result).unwrap();

        assert!(result_str.contains("x-api-key: real-key\r\n"));
        assert!(
            !result_str.contains("agent-fake-key"),
            "case-insensitive strip should remove X-Api-Key"
        );
    }

    #[test]
    fn inject_header_preserves_body() {
        let raw =
            b"POST /v1 HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 5\r\n\r\nhello";
        let injection = ResolvedInjection {
            target: InjectionTarget::Header {
                name: "x-api-key".to_string(),
                value_prefix: String::new(),
            },
            value: "key".to_string(),
        };

        let result = inject_credential(raw, &injection);
        let result_str = String::from_utf8(result).unwrap();

        assert!(result_str.ends_with("\r\n\r\nhello"));
        assert!(result_str.contains("Content-Length: 5\r\n"));
    }

    #[test]
    fn inject_query_param_no_existing_query() {
        let raw = b"GET /search HTTP/1.1\r\nHost: www.googleapis.com\r\n\r\n";
        let injection = ResolvedInjection {
            target: InjectionTarget::QueryParam {
                name: "key".to_string(),
            },
            value: "AIza-test".to_string(),
        };

        let result = inject_credential(raw, &injection);
        let result_str = String::from_utf8(result).unwrap();

        assert!(result_str.starts_with("GET /search?key=AIza-test HTTP/1.1\r\n"));
    }

    #[test]
    fn inject_query_param_with_existing_query() {
        let raw = b"GET /search?q=hello HTTP/1.1\r\nHost: www.googleapis.com\r\n\r\n";
        let injection = ResolvedInjection {
            target: InjectionTarget::QueryParam {
                name: "key".to_string(),
            },
            value: "AIza-test".to_string(),
        };

        let result = inject_credential(raw, &injection);
        let result_str = String::from_utf8(result).unwrap();

        assert!(result_str.starts_with("GET /search?q=hello&key=AIza-test HTTP/1.1\r\n"));
    }

    #[test]
    fn inject_query_param_encodes_special_chars() {
        let raw = b"GET /search HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let injection = ResolvedInjection {
            target: InjectionTarget::QueryParam {
                name: "key".to_string(),
            },
            value: "val=ue&more".to_string(),
        };

        let result = inject_credential(raw, &injection);
        let result_str = String::from_utf8(result).unwrap();

        assert!(result_str.starts_with("GET /search?key=val%3Due%26more HTTP/1.1\r\n"));
    }

    #[test]
    fn inject_query_param_preserves_body() {
        let raw =
            b"POST /data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc";
        let injection = ResolvedInjection {
            target: InjectionTarget::QueryParam {
                name: "key".to_string(),
            },
            value: "val".to_string(),
        };

        let result = inject_credential(raw, &injection);
        let result_str = String::from_utf8(result).unwrap();

        assert!(result_str.ends_with("\r\n\r\nabc"));
        assert!(result_str.starts_with("POST /data?key=val HTTP/1.1\r\n"));
    }

    #[test]
    fn url_encode_preserves_safe_chars() {
        assert_eq!(url_encode_param("abc123-_.~"), "abc123-_.~");
    }

    #[test]
    fn url_encode_encodes_special_chars() {
        assert_eq!(url_encode_param("a=b&c"), "a%3Db%26c");
        assert_eq!(url_encode_param("hello world"), "hello%20world");
    }

    #[test]
    fn glob_match_single_label() {
        assert!(glob_match_host("*.example.com", "api.example.com"));
        assert!(!glob_match_host(
            "*.example.com",
            "sub.api.example.com"
        ));
        assert!(!glob_match_host("*.example.com", "example.com"));
    }

    #[test]
    fn glob_match_multi_label() {
        assert!(glob_match_host("**.example.com", "api.example.com"));
        assert!(glob_match_host(
            "**.example.com",
            "sub.api.example.com"
        ));
        assert!(!glob_match_host("**.example.com", "example.com"));
    }

    #[test]
    fn no_injection_returns_empty() {
        let policy = SandboxPolicy::default();
        let provider_env: HashMap<String, String> =
            [("KEY".to_string(), "val".to_string())]
                .into_iter()
                .collect();

        let (injector, filtered_env) =
            CredentialInjector::extract_from_policy(&policy, provider_env);

        assert!(injector.is_empty());
        assert_eq!(filtered_env.get("KEY").unwrap(), "val");
    }
}
