//! Plugin system v1 — YAML-defined HTTP checks.
//!
//! Each `*.yaml` file in the app's `plugins/` dir defines one check: a request
//! path and a set of match conditions (status / body substring / body regex).
//! When all specified conditions hold against a target, Spectra emits a Finding.
//! This is the extensible foundation; WASM/native plugin runtimes can slot in
//! later behind the same Finding contract.

use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct RequestSpec {
    pub path: String,
    #[serde(default)]
    pub method: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct MatchSpec {
    pub status: Option<u16>,
    pub body_contains: Option<String>,
    pub body_regex: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PluginCheck {
    pub id: String,
    pub name: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    pub request: RequestSpec,
    #[serde(rename = "match", default)]
    pub match_spec: MatchSpec,
    #[serde(default)]
    pub recommendation: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_severity() -> String {
    "info".into()
}

/// Parse a single YAML check definition.
pub fn parse_plugin(yaml: &str) -> Result<PluginCheck, String> {
    serde_yaml_ng::from_str::<PluginCheck>(yaml).map_err(|e| e.to_string())
}

/// Load all `*.yaml`/`*.yml` checks in a directory (skips ones that fail to parse).
pub fn load_plugins(dir: &Path) -> Vec<PluginCheck> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.filter_map(|e| e.ok()) {
            if let Some(n) = entry.file_name().to_str() {
                if n.ends_with(".yaml") || n.ends_with(".yml") {
                    if let Ok(content) = std::fs::read_to_string(entry.path()) {
                        if let Ok(check) = parse_plugin(&content) {
                            out.push(check);
                        }
                    }
                }
            }
        }
    }
    out
}

/// Evaluate the match conditions (all specified conditions must hold). A check
/// with no conditions never matches, so a misconfigured plugin can't flag
/// every target.
pub fn check_matches(check: &PluginCheck, status: u16, body: &str) -> bool {
    let m = &check.match_spec;
    if m.status.is_none() && m.body_contains.is_none() && m.body_regex.is_none() {
        return false;
    }
    if let Some(s) = m.status {
        if s != status {
            return false;
        }
    }
    if let Some(sub) = &m.body_contains {
        if !body.contains(sub.as_str()) {
            return false;
        }
    }
    if let Some(re) = &m.body_regex {
        match regex::Regex::new(re) {
            Ok(r) => {
                if !r.is_match(body) {
                    return false;
                }
            }
            Err(_) => return false, // invalid regex → no match (fail closed)
        }
    }
    true
}

fn normalize_severity(s: &str) -> &'static str {
    match s.to_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        _ => "info",
    }
}

/// Build a Finding payload for a matched check.
pub fn check_to_finding(check: &PluginCheck, url: &str) -> serde_json::Value {
    let severity = normalize_severity(&check.severity);
    let mut tags = vec!["plugin".to_string()];
    tags.extend(check.tags.clone());
    serde_json::json!({
        "source": "plugin",
        "title": check.name,
        "severity": severity,
        "asset": url,
        "evidence": format!("Custom check '{}' matched at {}", check.id, url),
        "description": format!("Plugin check '{}' matched its conditions.", check.id),
        "recommendation": check.recommendation.clone().unwrap_or_else(|| "Review the matched condition and remediate.".to_string()),
        "tags": tags,
        "exploitability": match severity {
            "critical" => 80,
            "high" => 65,
            "medium" => 45,
            _ => 30,
        },
    })
}

/// Write a couple of example plugins on first run, so the dir isn't empty.
pub fn seed_example_plugins(dir: &Path) {
    let has_yaml = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .any(|e| e.file_name().to_str().map(|n| n.ends_with(".yaml") || n.ends_with(".yml")).unwrap_or(false))
        })
        .unwrap_or(false);
    if has_yaml {
        return;
    }
    let examples = [
        (
            "exposed-git.yaml",
            "id: exposed-git\nname: Exposed .git directory\nseverity: high\nrequest:\n  path: /.git/config\nmatch:\n  status: 200\n  body_contains: \"[core]\"\nrecommendation: Block external access to the .git directory.\ntags: [web, exposure]\n",
        ),
        (
            "exposed-env.yaml",
            "id: exposed-env\nname: Exposed .env file\nseverity: critical\nrequest:\n  path: /.env\nmatch:\n  status: 200\n  body_regex: \"(?i)(secret|api[_-]?key|password|token)\"\nrecommendation: Remove .env from the web root and rotate any exposed secrets.\ntags: [web, secrets]\n",
        ),
    ];
    for (name, content) in examples {
        let _ = std::fs::write(dir.join(name), content);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PluginCheck {
        parse_plugin(
            "id: exposed-env\nname: Exposed .env\nseverity: critical\nrequest:\n  path: /.env\nmatch:\n  status: 200\n  body_regex: \"(?i)secret\"\nrecommendation: Remove it.\ntags: [web, secrets]\n",
        )
        .unwrap()
    }

    #[test]
    fn parses_yaml_check() {
        let c = sample();
        assert_eq!(c.id, "exposed-env");
        assert_eq!(c.severity, "critical");
        assert_eq!(c.request.path, "/.env");
        assert_eq!(c.match_spec.status, Some(200));
        assert_eq!(c.tags, vec!["web", "secrets"]);
    }

    #[test]
    fn matches_when_all_conditions_hold() {
        let c = sample();
        assert!(check_matches(&c, 200, "DB_SECRET=hunter2"));
        assert!(!check_matches(&c, 404, "DB_SECRET=hunter2")); // wrong status
        assert!(!check_matches(&c, 200, "nothing here")); // regex miss
    }

    #[test]
    fn empty_match_never_fires() {
        let c = parse_plugin("id: x\nname: x\nrequest:\n  path: /\nmatch: {}\n").unwrap();
        assert!(!check_matches(&c, 200, "anything"));
    }

    #[test]
    fn invalid_regex_fails_closed() {
        let mut c = sample();
        c.match_spec.body_regex = Some("(unclosed".into());
        assert!(!check_matches(&c, 200, "secret"));
    }

    #[test]
    fn finding_payload_maps_severity_and_tags() {
        let f = check_to_finding(&sample(), "http://t/.env");
        assert_eq!(f["source"], "plugin");
        assert_eq!(f["severity"], "critical");
        assert_eq!(f["asset"], "http://t/.env");
        assert_eq!(f["exploitability"], 80);
        let tags = f["tags"].as_array().unwrap();
        assert!(tags.iter().any(|t| t == "plugin"));
        assert!(tags.iter().any(|t| t == "secrets"));
    }
}
