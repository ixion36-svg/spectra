//! Compliance / hardening checks (CIS-aligned). Each check runs a command on a
//! host and evaluates the output as pass/fail. Checks are batched into a single
//! remote script so one SSH round-trip covers the whole profile. Evaluation and
//! parsing are pure and unit-tested; the SSH transport is shared with auth_scan.

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Expect {
    /// Passes if the output matches this regex.
    Matches(String),
    /// Passes if the output does NOT match this regex.
    NotMatches(String),
    /// Passes if the trimmed output equals this string.
    Equals(String),
    /// Passes if the output is empty (e.g. "no world-writable files found").
    Empty,
    /// Passes if the output is non-empty.
    NonEmpty,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ComplianceCheck {
    pub id: String,
    pub title: String,
    pub command: String,
    pub expect: Expect,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default)]
    pub remediation: Option<String>,
}

fn default_severity() -> String {
    "medium".into()
}

/// Evaluate a check's expectation against captured command output.
pub fn evaluate(expect: &Expect, output: &str) -> bool {
    let trimmed = output.trim();
    match expect {
        Expect::Empty => trimmed.is_empty(),
        Expect::NonEmpty => !trimmed.is_empty(),
        Expect::Equals(s) => trimmed == s,
        Expect::Matches(re) => regex::Regex::new(re).map(|r| r.is_match(output)).unwrap_or(false),
        Expect::NotMatches(re) => regex::Regex::new(re).map(|r| !r.is_match(output)).unwrap_or(false),
    }
}

const MARKER: &str = "===SPECTRA_CHECK:";

/// Build one remote shell script that runs every check, delimiting each block.
pub fn build_remote_script(checks: &[ComplianceCheck]) -> String {
    checks
        .iter()
        .map(|c| format!("echo '{}{}==='; {{ {} ; }} 2>/dev/null", MARKER, c.id, c.command))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Split the batched output back into (check_id -> output) blocks.
pub fn split_output(output: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let mut current: Option<String> = None;
    let mut buf = String::new();
    for line in output.lines() {
        if let Some(rest) = line.strip_prefix(MARKER) {
            if let Some(id) = current.take() {
                map.insert(id, buf.trim().to_string());
                buf.clear();
            }
            current = rest.strip_suffix("===").map(|s| s.to_string());
        } else if current.is_some() {
            buf.push_str(line);
            buf.push('\n');
        }
    }
    if let Some(id) = current.take() {
        map.insert(id, buf.trim().to_string());
    }
    map
}

#[derive(Debug, Clone)]
pub struct CheckResult {
    pub check: ComplianceCheck,
    pub passed: bool,
    pub evidence: String,
}

/// Run a parsed batched output through the checks.
pub fn evaluate_results(checks: &[ComplianceCheck], output: &str) -> Vec<CheckResult> {
    let blocks = split_output(output);
    checks
        .iter()
        .map(|c| {
            let evidence = blocks.get(&c.id).cloned().unwrap_or_default();
            CheckResult { check: c.clone(), passed: evaluate(&c.expect, &evidence), evidence }
        })
        .collect()
}

/// Turn a check result into a Spectra finding payload (failures are findings;
/// passes are recorded as `info` so the profile coverage is visible).
pub fn result_to_finding(r: &CheckResult, asset: &str) -> serde_json::Value {
    let severity = if r.passed { "info" } else { normalize_severity(&r.check.severity) };
    serde_json::json!({
        "source": "compliance",
        "title": format!("[{}] {}", if r.passed { "PASS" } else { "FAIL" }, r.check.title),
        "severity": severity,
        "asset": asset,
        "evidence": if r.evidence.is_empty() { "(no output)".to_string() } else { r.evidence.chars().take(300).collect() },
        "description": format!("CIS compliance check '{}'.", r.check.id),
        "recommendation": r.check.remediation.clone().unwrap_or_else(|| "Review against the CIS benchmark.".into()),
        "tags": ["compliance", "cis", if r.passed { "pass" } else { "fail" }],
        "exploitability": if r.passed { 0 } else { 40 },
    })
}

fn normalize_severity(s: &str) -> &'static str {
    match s.to_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "low" => "low",
        "info" => "info",
        _ => "medium",
    }
}

/// Built-in CIS-aligned Linux checks (a starter profile; extend via YAML).
pub fn builtin_checks() -> Vec<ComplianceCheck> {
    vec![
        ComplianceCheck {
            id: "ssh-root-login".into(),
            title: "SSH root login disabled".into(),
            command: "grep -Ei '^[[:space:]]*PermitRootLogin' /etc/ssh/sshd_config || echo 'not set'".into(),
            expect: Expect::NotMatches("(?i)permitrootlogin[[:space:]]+yes".into()),
            severity: "high".into(),
            remediation: Some("Set 'PermitRootLogin no' (or 'prohibit-password') in /etc/ssh/sshd_config.".into()),
        },
        ComplianceCheck {
            id: "ssh-password-auth".into(),
            title: "SSH password authentication disabled".into(),
            command: "grep -Ei '^[[:space:]]*PasswordAuthentication' /etc/ssh/sshd_config || echo 'not set'".into(),
            expect: Expect::NotMatches("(?i)passwordauthentication[[:space:]]+yes".into()),
            severity: "medium".into(),
            remediation: Some("Set 'PasswordAuthentication no' and use keys.".into()),
        },
        ComplianceCheck {
            id: "ip-forwarding".into(),
            title: "IP forwarding disabled".into(),
            command: "sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0".into(),
            expect: Expect::Equals("0".into()),
            severity: "low".into(),
            remediation: Some("Set net.ipv4.ip_forward=0 unless the host is a router.".into()),
        },
        ComplianceCheck {
            id: "empty-passwords".into(),
            title: "No accounts with empty passwords".into(),
            command: "awk -F: '($2==\"\"){print $1}' /etc/shadow 2>/dev/null".into(),
            expect: Expect::Empty,
            severity: "critical".into(),
            remediation: Some("Lock or set passwords for any account with an empty password field.".into()),
        },
        ComplianceCheck {
            id: "world-writable-files".into(),
            title: "No world-writable files in system paths".into(),
            command: "find /etc /usr/bin /usr/sbin -xdev -type f -perm -0002 2>/dev/null | head -3".into(),
            expect: Expect::Empty,
            severity: "medium".into(),
            remediation: Some("Remove world-write (chmod o-w) from the listed files.".into()),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluate_all_expectations() {
        assert!(evaluate(&Expect::Equals("0".into()), " 0\n"));
        assert!(!evaluate(&Expect::Equals("0".into()), "1"));
        assert!(evaluate(&Expect::Empty, "   \n"));
        assert!(evaluate(&Expect::NonEmpty, "x"));
        assert!(evaluate(&Expect::Matches("(?i)yes".into()), "PermitRootLogin YES"));
        assert!(evaluate(&Expect::NotMatches("(?i)permitrootlogin[[:space:]]+yes".into()), "PermitRootLogin no"));
        assert!(!evaluate(&Expect::NotMatches("(?i)permitrootlogin[[:space:]]+yes".into()), "PermitRootLogin yes"));
    }

    #[test]
    fn builds_and_splits_batched_output() {
        let checks = builtin_checks();
        let script = build_remote_script(&checks);
        assert!(script.contains("===SPECTRA_CHECK:ssh-root-login==="));
        // simulate the host's response
        let output = "\
===SPECTRA_CHECK:ssh-root-login===
PermitRootLogin yes
===SPECTRA_CHECK:ssh-password-auth===
PasswordAuthentication no
===SPECTRA_CHECK:ip-forwarding===
0
===SPECTRA_CHECK:empty-passwords===
===SPECTRA_CHECK:world-writable-files===
";
        let results = evaluate_results(&checks, output);
        let by = |id: &str| results.iter().find(|r| r.check.id == id).unwrap();
        assert!(!by("ssh-root-login").passed); // PermitRootLogin yes -> FAIL
        assert!(by("ssh-password-auth").passed); // no -> PASS
        assert!(by("ip-forwarding").passed); // 0 -> PASS
        assert!(by("empty-passwords").passed); // empty -> PASS
        assert!(by("world-writable-files").passed); // empty -> PASS
    }

    #[test]
    fn result_to_finding_marks_pass_fail() {
        let checks = builtin_checks();
        let fail = CheckResult { check: checks[0].clone(), passed: false, evidence: "PermitRootLogin yes".into() };
        let f = result_to_finding(&fail, "h");
        assert_eq!(f["source"], "compliance");
        assert_eq!(f["severity"], "high");
        assert!(f["title"].as_str().unwrap().starts_with("[FAIL]"));
        let pass = CheckResult { check: checks[0].clone(), passed: true, evidence: "no".into() };
        assert_eq!(result_to_finding(&pass, "h")["severity"], "info");
    }
}
