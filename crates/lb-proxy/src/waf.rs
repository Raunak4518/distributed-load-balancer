//! WAF first slice -- see `ProxyContext::waf`.
//!
//! A small, fixed, built-in set of case-folded substring checks against a
//! request's path and query string, run before anything backend-affecting
//! happens (the cluster rate-limit budget, the response cache, route
//! resolution, a backend). Deliberately not a rule engine: no
//! percent-decoding/canonicalization (an encoded bypass is a real evasion,
//! but out of scope for a first slice), no header inspection (`User-Agent`/
//! `Referer`/`Cookie` are common vectors too, but path+query alone is
//! naxsi's own "core" scope), and no operator-supplied patterns -- both a
//! new dependency (regex, nowhere else in this workspace) and a ReDoS-on-
//! operator-input question that deserve their own deliberate decision, not
//! a rider on this one.

use lb_metrics::WafRule;

const SQL_INJECTION_TOKENS: &[&str] = &[
    "union select",
    "' or '1'='1",
    "or 1=1",
    "drop table",
    "insert into",
    "xp_cmdshell",
    "sleep(",
    "benchmark(",
    ";--",
];

const XSS_TOKENS: &[&str] = &[
    "<script",
    "javascript:",
    "onerror=",
    "onload=",
    "<svg/onload",
    "<img src=x",
];

const PATH_TRAVERSAL_TOKENS: &[&str] = &["../", "..\\", "%2e%2e%2f", "%2e%2e/", "..%2f"];

/// The first built-in rule (checked in a fixed order: SQL injection, then
/// XSS, then path traversal) whose token list matches anywhere in `target`
/// (a request's path, or path+query), or `None` if nothing matched.
/// Case-insensitive: `target` is lower-cased once, so the token lists above
/// only need to spell each token in lowercase.
pub fn matched_rule(target: &str) -> Option<WafRule> {
    let lower = target.to_ascii_lowercase();
    if SQL_INJECTION_TOKENS.iter().any(|t| lower.contains(t)) {
        return Some(WafRule::SqlInjection);
    }
    if XSS_TOKENS.iter().any(|t| lower.contains(t)) {
        return Some(WafRule::Xss);
    }
    if PATH_TRAVERSAL_TOKENS.iter().any(|t| lower.contains(t)) {
        return Some(WafRule::PathTraversal);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_a_sql_injection_token() {
        assert_eq!(
            matched_rule("/search?q=1 UNION SELECT password FROM users"),
            Some(WafRule::SqlInjection)
        );
    }

    #[test]
    fn detects_an_xss_token() {
        assert_eq!(
            matched_rule("/comment?body=<script>alert(1)</script>"),
            Some(WafRule::Xss)
        );
    }

    #[test]
    fn detects_a_path_traversal_token() {
        assert_eq!(
            matched_rule("/files/../../etc/passwd"),
            Some(WafRule::PathTraversal)
        );
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert_eq!(
            matched_rule("/search?q=1 uNiOn SeLeCt password"),
            Some(WafRule::SqlInjection)
        );
        assert_eq!(
            matched_rule("/comment?body=<SCRIPT>alert(1)</SCRIPT>"),
            Some(WafRule::Xss)
        );
    }

    #[test]
    fn a_benign_request_is_not_matched() {
        assert_eq!(matched_rule("/orders?page=2&sort=recent"), None);
    }

    #[test]
    fn a_match_in_the_query_string_is_detected_not_just_the_path() {
        assert_eq!(
            matched_rule("/api/users?redirect=javascript:alert(1)"),
            Some(WafRule::Xss)
        );
    }

    #[test]
    fn sql_injection_is_checked_before_xss_when_both_would_match() {
        // Declaration order: SQL injection first -- this is what "first
        // match wins" resolves to when a (contrived) request contains
        // tokens from more than one category.
        assert_eq!(
            matched_rule("/x?q=UNION SELECT * FROM t&y=<script>"),
            Some(WafRule::SqlInjection)
        );
    }
}
