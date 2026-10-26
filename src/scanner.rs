//! Secret / PII detection and masking.
//!
//! Stage 1: one Aho-Corasick automaton over every rule's literal prefix (`AKIA`,
//!          `sk_live_`, `postgres://`, ...). A prefix hit triggers that rule's
//!          anchored regex, which determines the exact extent of the secret.
//! Stage 2: regex-only rules with no usable literal prefix (email, phone, SSN,
//!          card numbers, `key = value` assignments with high entropy).
//! Stage 3: optional user deny-terms through a second, case-insensitive automaton.
//!
//! Overlaps are resolved by priority (secrets > entropy/terms > PII), then by length.

use std::collections::BTreeMap;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::{Captures, Regex};
use serde_json::Value;

use crate::{error::FirewallError, state::Session};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finding {
    pub start: usize,
    pub end: usize,
    pub kind: &'static str,
    priority: u8,
}

struct Rule {
    kind: &'static str,
    prefixes: &'static [&'static str],
    re: Regex,
    /// Capture group whose span is masked (0 = whole match).
    group: usize,
    priority: u8,
    /// Require a non-word character before an anchored prefix hit.
    boundary: bool,
    validator: Option<fn(&str) -> bool>,
}

impl Rule {
    fn eval(&self, caps: &Captures<'_>, offset: usize) -> Option<Finding> {
        let g = caps.get(self.group)?;
        if g.start() == g.end() {
            return None;
        }
        if let Some(v) = self.validator {
            if !v(g.as_str()) {
                return None;
            }
        }
        Some(Finding {
            start: offset + g.start(),
            end: offset + g.end(),
            kind: self.kind,
            priority: self.priority,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn rule(
    kind: &'static str,
    prefixes: &'static [&'static str],
    pattern: &str,
    group: usize,
    priority: u8,
    boundary: bool,
    validator: Option<fn(&str) -> bool>,
) -> Result<Rule, FirewallError> {
    Ok(Rule {
        kind,
        prefixes,
        re: Regex::new(pattern)?,
        group,
        priority,
        boundary,
        validator,
    })
}

fn builtin_rules() -> Result<Vec<Rule>, FirewallError> {
    Ok(vec![
        // ---- Stage 1: prefix-anchored credentials (priority 0) ----
        rule(
            "AWS_ACCESS_KEY",
            &[
                "AKIA", "ASIA", "AGPA", "AIDA", "AROA", "ANPA", "ANVA", "AIPA",
            ],
            r"\A(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b",
            0,
            0,
            true,
            None,
        )?,
        rule(
            "STRIPE_KEY",
            &[
                "sk_live_",
                "rk_live_",
                "pk_live_",
                "sk_test_",
                "rk_test_",
                "pk_test_",
            ],
            r"\A(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}",
            0,
            0,
            true,
            None,
        )?,
        // Must precede the generic OpenAI "sk-" rule (LeftmostFirst picks the earlier pattern).
        rule(
            "ANTHROPIC_KEY",
            &["sk-ant-"],
            r"\Ask-ant-[A-Za-z0-9_\-]{20,}",
            0,
            0,
            true,
            None,
        )?,
        rule(
            "OPENAI_KEY",
            &["sk-"],
            r"\Ask-[A-Za-z0-9_\-]{20,}",
            0,
            0,
            true,
            None,
        )?,
        rule(
            "GITHUB_TOKEN",
            &["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"],
            r"\A(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})",
            0,
            0,
            true,
            None,
        )?,
        rule(
            "SLACK_TOKEN",
            &["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"],
            r"\Axox[abprs]-[A-Za-z0-9\-]{10,}",
            0,
            0,
            true,
            None,
        )?,
        rule(
            "GOOGLE_API_KEY",
            &["AIza"],
            // These keys have 35 characters after the prefix; prevent matching a longer ID prefix.
            r"\AAIza[0-9A-Za-z_\-]{35}\b",
            0,
            0,
            true,
            None,
        )?,
        rule(
            "JWT",
            &["eyJ"],
            r"\AeyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
            0,
            0,
            true,
            None,
        )?,
        rule(
            "DB_CONNECTION_STRING",
            &[
                "postgres://",
                "postgresql://",
                "mysql://",
                "mariadb://",
                "mongodb://",
                "mongodb+srv://",
                "redis://",
                "rediss://",
                "amqp://",
                "amqps://",
                "mssql://",
                "sqlserver://",
                "clickhouse://",
            ],
            r#"\A[a-z][a-z0-9+.\-]*://[^\s/@'"<>`]+@[^\s'"<>`)\]]*[^\s'"<>`)\].,;]"#,
            0,
            0,
            true,
            None,
        )?,
        rule(
            "URL_CREDENTIALS",
            &["http://", "https://"],
            r#"\Ahttps?://[^\s/@:'"<>`]+:[^\s/@'"<>`]+@[^\s'"<>`)\]]*[^\s'"<>`)\].,;]"#,
            0,
            0,
            true,
            None,
        )?,
        rule(
            "PRIVATE_KEY",
            &["-----BEGIN"],
            r"(?s)\A-----BEGIN [A-Z ]*PRIVATE KEY-----(?:.*?-----END [A-Z ]*PRIVATE KEY-----|[A-Za-z0-9+/=\s]{40,})",
            0,
            0,
            false,
            None,
        )?,
        rule(
            "BEARER_TOKEN",
            &["Bearer ", "bearer "],
            r"\A[Bb]earer\s+([A-Za-z0-9\-._~+/]{20,}=*)",
            1,
            0,
            true,
            None,
        )?,
        // ---- Stage 2: floating rules ----
        rule(
            "SECRET",
            &[],
            // Allow prefixed env/config names such as SERVICE_SECRET while validating the value.
            r#"(?i)\b(?:[A-Za-z0-9]+[_\-])*(?:api[_\-]?key|secret|token|passw(?:or)?d|pwd|credential|auth)[A-Za-z0-9_\-]*["']?\s*[:=]\s*["']?([A-Za-z0-9/+_.\-=]{12,})"#,
            1,
            1,
            false,
            Some(high_entropy),
        )?,
        rule(
            "EMAIL",
            &[],
            // Consume the left boundary outside the capture so matching cannot start at a
            // valid-looking suffix after malformed local-part punctuation such as `..`.
            r"(?:\A|[^A-Za-z0-9._%+\-])([A-Za-z0-9_%+\-]+(?:\.[A-Za-z0-9_%+\-]+)*@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{1,}\b)",
            1,
            2,
            false,
            None,
        )?,
        rule(
            "PHONE",
            &[],
            r"(?:\+\d{1,3}[\s.\-]?)?(?:\(\d{3}\)\s?|\b\d{3}[\s.\-])[2-9]\d{2}[\s.\-]\d{4}\b",
            0,
            2,
            false,
            None,
        )?,
        rule("SSN", &[], r"\b\d{3}-\d{2}-\d{4}\b", 0, 2, false, None)?,
        rule(
            "CREDIT_CARD",
            &[],
            r"\b(?:\d[ \-]?){12,18}\d\b",
            0,
            2,
            false,
            Some(luhn_valid),
        )?,
    ])
}

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn high_entropy(s: &str) -> bool {
    s.len() >= 12
        && s.bytes().any(|b| b.is_ascii_digit())
        && s.bytes().any(|b| b.is_ascii_alphabetic())
        && shannon_entropy(s) >= 3.0
}

fn luhn_valid(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let mut sum = 0u32;
    for (i, d) in digits.iter().rev().enumerate() {
        let mut v = *d;
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum % 10 == 0
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn boundary_before(text: &str, pos: usize) -> bool {
    text[..pos].chars().next_back().is_none_or(|c| !is_word(c))
}

fn boundary_after(text: &str, pos: usize) -> bool {
    text[pos..].chars().next().is_none_or(|c| !is_word(c))
}

pub struct Scanner {
    rules: Vec<Rule>,
    prefix_ac: AhoCorasick,
    /// Aho-Corasick pattern index -> rule index.
    pattern_rule: Vec<usize>,
    /// Rules without literal prefixes (evaluated with `captures_iter`).
    floating: Vec<usize>,
    term_ac: Option<AhoCorasick>,
}

impl Scanner {
    pub fn new(custom_terms: &[String]) -> Result<Self, FirewallError> {
        let rules = builtin_rules()?;

        let mut patterns: Vec<&'static str> = Vec::new();
        let mut pattern_rule: Vec<usize> = Vec::new();
        let mut floating: Vec<usize> = Vec::new();
        for (ri, r) in rules.iter().enumerate() {
            if r.prefixes.is_empty() {
                floating.push(ri);
            }
            for p in r.prefixes {
                patterns.push(p);
                pattern_rule.push(ri);
            }
        }
        let prefix_ac = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostFirst)
            .build(patterns.iter())?;

        let terms: Vec<&str> = custom_terms
            .iter()
            .map(|t| t.trim())
            .filter(|t| !t.is_empty())
            .collect();
        let term_ac = if terms.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::LeftmostLongest)
                    .ascii_case_insensitive(true)
                    .build(terms.iter())?,
            )
        };

        Ok(Self {
            rules,
            prefix_ac,
            pattern_rule,
            floating,
            term_ac,
        })
    }

    /// Built-in detection kinds included by this scanner instance.
    pub fn detection_kinds(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.rules.iter().map(|rule| rule.kind)
    }

    /// Returns non-overlapping findings sorted by start offset.
    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let mut cands: Vec<Finding> = Vec::new();

        for m in self.prefix_ac.find_iter(text) {
            let rule = &self.rules[self.pattern_rule[m.pattern().as_usize()]];
            let start = m.start();
            if rule.boundary && !boundary_before(text, start) {
                continue;
            }
            if let Some(caps) = rule.re.captures(&text[start..]) {
                if let Some(f) = rule.eval(&caps, start) {
                    cands.push(f);
                }
            }
        }

        for &ri in &self.floating {
            let rule = &self.rules[ri];
            for caps in rule.re.captures_iter(text) {
                if let Some(f) = rule.eval(&caps, 0) {
                    cands.push(f);
                }
            }
        }

        if let Some(ac) = &self.term_ac {
            for m in ac.find_iter(text) {
                if boundary_before(text, m.start()) && boundary_after(text, m.end()) {
                    cands.push(Finding {
                        start: m.start(),
                        end: m.end(),
                        kind: "TERM",
                        priority: 1,
                    });
                }
            }
        }

        cands.sort_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then((b.end - b.start).cmp(&(a.end - a.start)))
                .then(a.start.cmp(&b.start))
        });

        let mut accepted: BTreeMap<usize, Finding> = BTreeMap::new();
        for c in cands {
            let overlaps = accepted
                .range(..c.end)
                .next_back()
                .is_some_and(|(_, f)| f.end > c.start);
            if !overlaps {
                accepted.insert(c.start, c);
            }
        }
        accepted.into_values().collect()
    }

    /// Masks `text`; returns `None` when nothing was found (no allocation in the common case).
    pub fn mask_text(&self, text: &str, session: &Session) -> Option<(String, usize)> {
        let findings = self.scan(text);
        if findings.is_empty() {
            return None;
        }
        let mut out = String::with_capacity(text.len());
        let mut last = 0usize;
        for f in &findings {
            out.push_str(&text[last..f.start]);
            out.push_str(&session.tokenize(f.kind, &text[f.start..f.end]));
            last = f.end;
        }
        out.push_str(&text[last..]);
        Some((out, findings.len()))
    }

    /// Masks every string value inside a JSON document (so escapes like `\n` or `\"`
    /// never hide a secret). Returns the number of replacements.
    pub fn mask_json(&self, v: &mut Value, session: &Session) -> usize {
        match v {
            Value::String(s) => {
                if s.len() < 5 {
                    return 0;
                }
                match self.mask_text(s, session) {
                    Some((masked, n)) => {
                        *s = masked;
                        n
                    }
                    None => 0,
                }
            }
            Value::Array(a) => a.iter_mut().map(|x| self.mask_json(x, session)).sum(),
            Value::Object(o) => o.values_mut().map(|x| self.mask_json(x, session)).sum(),
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::SessionRegistry;

    #[test]
    fn masks_db_uri_stripe_key_and_email() {
        let sc = Scanner::new(&[]).unwrap();
        let reg = SessionRegistry::new();
        let s = reg.create();
        let stripe_key = concat!("sk_", "live_51PabcdefghijklmnopqrSTUV");
        let input = format!("conn=postgres://admin:p@ssword@db.local:5432/prod key={stripe_key} mail bob@example.com");
        let (masked, n) = sc.mask_text(&input, &s).unwrap();
        assert_eq!(n, 3);
        assert!(!masked.contains("p@ssword"));
        assert!(!masked.contains(&stripe_key));
        assert!(!masked.contains("bob@example.com"));
        assert!(masked.contains("[DB_CONNECTION_STRING_"));
    }

    #[test]
    fn aws_key_needs_boundary() {
        let sc = Scanner::new(&[]).unwrap();
        assert_eq!(sc.scan("id AKIAABCDEFGHIJKLMNOP end").len(), 1);
        assert!(sc.scan("xAKIAABCDEFGHIJKLMNOP").is_empty());
    }

    #[test]
    fn luhn_filters_random_digit_runs() {
        let sc = Scanner::new(&[]).unwrap();
        assert_eq!(sc.scan("card 4111 1111 1111 1111 ok").len(), 1);
        assert!(sc.scan("order 1234 5678 9012 3456 ok").is_empty());
    }

    #[test]
    fn deny_terms_are_masked_case_insensitively() {
        let sc = Scanner::new(&["John Doe".to_string()]).unwrap();
        let reg = SessionRegistry::new();
        let s = reg.create();
        let (masked, _) = sc.mask_text("ask john doe about it", &s).unwrap();
        assert!(masked.contains("[TERM_"));
        assert!(!masked.to_lowercase().contains("john doe"));
    }

    #[test]
    fn project_falcon_matches_whole_unicode_words_and_multiple_occurrences() {
        let sc = Scanner::new(&["Project Falcon".to_string()]).unwrap();
        let input = "Project Falcon, project falcon; XProject Falcon and Project Falconé";
        let findings = sc.scan(input);
        assert_eq!(findings.len(), 2);
        let reg = SessionRegistry::new();
        let (masked, count) = sc.mask_text(input, &reg.create()).unwrap();
        assert_eq!(count, 2);
        assert!(masked.contains("XProject Falcon"));
        assert!(masked.contains("Project Falconé"));
        assert!(!masked.contains("project falcon;"));
    }

    #[test]
    fn unicode_before_findings_keeps_byte_boundaries_valid() {
        let sc = Scanner::new(&["Falcon".to_string()]).unwrap();
        let reg = SessionRegistry::new();
        let (masked, n) = sc.mask_text("🦅 Falcon", &reg.create()).unwrap();
        assert_eq!(n, 1);
        assert!(masked.starts_with("🦅 "));
    }

    #[test]
    fn overlapping_terms_do_not_corrupt_or_duplicate_matches() {
        let sc = Scanner::new(&["Project Falcon".into(), "Falcon".into()]).unwrap();
        assert_eq!(sc.scan("Project Falcon").len(), 1);
    }

    #[test]
    fn every_builtin_rule_has_positive_and_negative_regressions() {
        let sc = Scanner::new(&[]).unwrap();
        let cases = [
            ("AWS_ACCESS_KEY", "AKIAABCDEFGHIJKLMNOP", "xAKIAABCDEFGHIJKLMNOP"),
            (
                "STRIPE_KEY",
                concat!("sk_", "live_51H8abcdefghijklmnop"),
                concat!("sk_", "live_12345"),
            ),
            (
                "ANTHROPIC_KEY",
                "sk-ant-api03-abcdefghijklmnopqrstuv",
                "sk-ant-api03-short",
            ),
            ("OPENAI_KEY", "sk-proj-abcdefghijklmnopqrstuv", "sk-short"),
            (
                "GITHUB_TOKEN",
                "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
                "ghp_short",
            ),
            ("SLACK_TOKEN", "xoxb-1234567890-FAKE", "xoxb-short"),
            (
                "GOOGLE_API_KEY",
                "AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "AIza12345",
            ),
            (
                "JWT",
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.c2lnbmF0dXJlMTIz",
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0",
            ),
            (
                "DB_CONNECTION_STRING",
                "postgres://demo:synthetic-pass@db.example.test/app",
                "postgres://db.example.test/app",
            ),
            (
                "URL_CREDENTIALS",
                "https://demo:synthetic-pass@service.example.test/path",
                "https://service.example.test/path",
            ),
            (
                "PRIVATE_KEY",
                "-----BEGIN PRIVATE KEY-----\nRkFLRV9LRVlfREFUQV9OT1RfUkVBTF9LRVk=\n-----END PRIVATE KEY-----",
                "-----BEGIN PRIVATE KEY-----\nshort\n",
            ),
            (
                "BEARER_TOKEN",
                "Bearer fake-token_0123456789abcdefgh",
                "Bearer short",
            ),
            (
                "SECRET",
                "api_key=Qx7mR2pL9vT4kN8c",
                "api_key=aaaaaaaaaaaaaaaa",
            ),
            (
                "EMAIL",
                "alerts+synthetic@service.example.test",
                "alerts..synthetic@service.example.test",
            ),
            ("PHONE", "+1 (415) 555-0132", "415-155-0132"),
            ("SSN", "900-12-3456", "900-12-345"),
            (
                "CREDIT_CARD",
                "4111 1111 1111 1111",
                "4111 1111 1111 1112",
            ),
        ];

        for (kind, positive, negative) in cases {
            assert!(
                sc.scan(positive).iter().any(|finding| finding.kind == kind),
                "expected {kind} to match its synthetic positive case"
            );
            assert!(
                sc.scan(negative).iter().all(|finding| finding.kind != kind),
                "unexpected {kind} match in its negative case"
            );
        }
        let kinds: std::collections::BTreeSet<_> = sc.detection_kinds().collect();
        assert_eq!(kinds.len(), cases.len(), "rule matrix should cover every built-in kind");
        let overlong_google_key = format!("AIza{}A", "A".repeat(35));
        assert!(sc
            .scan(&overlong_google_key)
            .iter()
            .all(|finding| finding.kind != "GOOGLE_API_KEY"));
        let stripe_publishable = concat!("pk_", "test_ABCDEFGHIJKLMNOP");
        assert!(sc
            .scan(&stripe_publishable)
            .iter()
            .any(|finding| finding.kind == "STRIPE_KEY"));
        assert!(sc
            .scan("SERVICE_SECRET=V8pL3nQ6xR1tM9wK")
            .iter()
            .any(|finding| finding.kind == "SECRET"));
    }

    #[test]
    fn repeated_and_multiple_findings_are_stable_sorted_and_non_overlapping() {
        let sc = Scanner::new(&[]).unwrap();
        let text = "AKIAABCDEFGHIJKLMNOP / AKIAABCDEFGHIJKLMNOP / sk-proj-abcdefghijklmnopqrstuv / dev@example.test";
        let first = sc.scan(text);
        let second = sc.scan(text);
        assert_eq!(first, second);
        assert_eq!(
            first.iter().map(|f| f.kind).collect::<Vec<_>>(),
            ["AWS_ACCESS_KEY", "AWS_ACCESS_KEY", "OPENAI_KEY", "EMAIL"]
        );
        assert!(first.windows(2).all(|pair| pair[0].start < pair[1].start));
        assert!(first.windows(2).all(|pair| pair[0].end <= pair[1].start));

        let session = SessionRegistry::new().create();
        let (masked, count) = sc.mask_text(text, &session).unwrap();
        assert_eq!(count, 4);
        let first_placeholder = &masked[..masked.find(" / ").unwrap()];
        let second_start = masked.find(" / ").unwrap() + 3;
        let second_end = masked[second_start..].find(" / ").unwrap() + second_start;
        assert_eq!(first_placeholder, &masked[second_start..second_end]);
    }
}
