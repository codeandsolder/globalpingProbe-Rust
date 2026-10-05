//! Input validation for untrusted measurement parameters.
//!
//! Measurement jobs arrive from the API as JSON and their string fields
//! (`target`, `resolver`, `Host`, …) are handed to system binaries
//! (`ping`, `traceroute`, `mtr`, `dig`, `curl`, `openssl`). Even though every
//! command is spawned with an explicit argv (no shell), a value that *starts
//! with `-`* is interpreted by those binaries as an **option, not a hostname**
//! — classic argument injection. A value containing shell metacharacters is
//! additionally dangerous anywhere a value might reach a shell.
//!
//! These helpers enforce a strict allow-list so a hostile or compromised API
//! cannot smuggle flags or shell syntax through a measurement target.

use std::net::IpAddr;

/// Maximum length of a DNS name per RFC 1035.
const MAX_HOST_LEN: usize = 253;

/// Returns `true` if `s` is safe to pass to a network tool as a host/target.
///
/// Accepts:
/// - any valid IPv4/IPv6 literal (private-range filtering is handled separately
///   by [`crate::util::private_ip::is_ip_private`]), or
/// - a DNS hostname using only `[A-Za-z0-9._-]`, not starting with `-`, `.`, or `_`.
///
/// Rejects anything else — in particular leading dashes (argument injection),
/// whitespace, and shell metacharacters (`; | & $ \` ( ) < > ' " \\` …).
#[must_use]
pub fn is_safe_host(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_HOST_LEN {
        return false;
    }

    // IP literals are always structurally safe; range policy is enforced elsewhere.
    if s.parse::<IpAddr>().is_ok() {
        return true;
    }

    // Hostname: must not start with a separator/dash, and may only contain
    // unreserved DNS characters. Underscore is permitted for DNS service labels
    // (e.g. `_dmarc.example.com`, `_25._tcp...`).
    let first = s.as_bytes()[0];
    if first == b'-' || first == b'.' {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

/// Returns `true` if `s` is safe to embed in a URL path or query string.
///
/// The path/query become part of a single curl URL argument, so the concern is
/// not argument injection but request smuggling: reject ASCII control characters
/// (CR/LF/NUL) and whitespace. Other URL characters (`/ ? = & % # …`) are allowed.
#[must_use]
pub fn is_safe_url_component(s: &str) -> bool {
    !s.bytes().any(|b| b.is_ascii_control() || b == b' ')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_hostnames() {
        assert!(is_safe_host("example.com"));
        assert!(is_safe_host("a.b.c.example.co.uk"));
        assert!(is_safe_host("_dmarc.example.com"));
        assert!(is_safe_host("xn--nxasmq6b.example")); // punycode IDN
        assert!(is_safe_host("host-name123.net"));
    }

    #[test]
    fn accepts_ip_literals() {
        assert!(is_safe_host("1.1.1.1"));
        assert!(is_safe_host("8.8.8.8"));
        assert!(is_safe_host("2606:4700:4700::1111"));
        assert!(is_safe_host("::1"));
        assert!(is_safe_host("::ffff:127.0.0.1"));
    }

    #[test]
    fn rejects_leading_dash_argument_injection() {
        // The core argument-injection vectors.
        assert!(!is_safe_host("-O"));
        assert!(!is_safe_host("--help"));
        assert!(!is_safe_host("-f/etc/passwd"));
        assert!(!is_safe_host("-oxx"));
        assert!(!is_safe_host("--resolve=evil"));
    }

    #[test]
    fn rejects_shell_metacharacters() {
        assert!(!is_safe_host("evil.com; touch /tmp/pwned"));
        assert!(!is_safe_host("$(id)"));
        assert!(!is_safe_host("`id`"));
        assert!(!is_safe_host("a|b"));
        assert!(!is_safe_host("a&b"));
        assert!(!is_safe_host("a>b"));
        assert!(!is_safe_host("a b"));
        assert!(!is_safe_host("a\nb"));
        assert!(!is_safe_host("evil.com\r\nHost: other"));
        assert!(!is_safe_host("a'b"));
        assert!(!is_safe_host("a\"b"));
        assert!(!is_safe_host("a\\b"));
        assert!(!is_safe_host("a/b")); // slash is not valid in a hostname
        assert!(!is_safe_host("a@b")); // '@' is dig's resolver sigil
    }

    #[test]
    fn rejects_empty_and_oversized() {
        assert!(!is_safe_host(""));
        assert!(!is_safe_host(&"a".repeat(254)));
        assert!(!is_safe_host(".leadingdot.com"));
    }

    #[test]
    fn url_component_rejects_control_and_space() {
        assert!(is_safe_url_component("/path/to/page?x=1&y=2"));
        assert!(is_safe_url_component("/%20encoded"));
        assert!(!is_safe_url_component("/path with space"));
        assert!(!is_safe_url_component("/path\r\nInjected: header"));
        assert!(!is_safe_url_component("/null\0byte"));
    }
}
