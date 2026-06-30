//! Offline CVE matching engine — the core of OpenVAS-style vulnerability
//! detection, fed by the free NVD data and run entirely on-box (air-gap safe).
//!
//! CVEs (with affected product + version ranges) are stored in SQLite; a
//! detected service version (e.g. from nmap -sV or an HTTP `Server` banner) is
//! matched against them to surface concrete CVEs with CVSS + severity.

use rusqlite::Connection;
use serde::Serialize;
use std::cmp::Ordering;

pub fn init_cve_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS cve (
            cve_id             TEXT NOT NULL,
            vendor             TEXT NOT NULL,
            product            TEXT NOT NULL,
            version_start      TEXT,                       -- null = no lower bound
            version_start_incl INTEGER NOT NULL DEFAULT 1,
            version_end        TEXT,                       -- null = no upper bound
            version_end_incl   INTEGER NOT NULL DEFAULT 0,
            cvss               REAL,
            severity           TEXT,
            summary            TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_cve_product ON cve(product);

        -- CISA Known Exploited Vulnerabilities (KEV) — CVEs seen exploited in the wild.
        CREATE TABLE IF NOT EXISTS kev (
            cve_id              TEXT PRIMARY KEY,
            vendor_project      TEXT,
            product             TEXT,
            vuln_name           TEXT,
            date_added          TEXT,
            due_date            TEXT,
            known_ransomware    INTEGER NOT NULL DEFAULT 0,
            short_description   TEXT
        );",
    )?;
    Ok(())
}

// ── Version comparison ───────────────────────────────────────────────────────
// Dotted-numeric, component-wise (handles differing lengths by zero-padding).
// Non-numeric suffixes within a component are dropped (e.g. "2.4.49a" -> 2,4,49).
// Good enough for the overwhelmingly dotted-numeric world of product versions;
// epoch/build-metadata edge cases are out of scope for v1.

fn version_parts(v: &str) -> Vec<u64> {
    v.split(|c: char| c == '.' || c == '-' || c == '_' || c == '+' || c == '~')
        .map(|p| p.chars().take_while(|c| c.is_ascii_digit()).collect::<String>())
        .map(|s| s.parse::<u64>().unwrap_or(0))
        .collect()
}

pub fn cmp_versions(a: &str, b: &str) -> Ordering {
    let (pa, pb) = (version_parts(a), version_parts(b));
    let n = pa.len().max(pb.len());
    for i in 0..n {
        let x = pa.get(i).copied().unwrap_or(0);
        let y = pb.get(i).copied().unwrap_or(0);
        match x.cmp(&y) {
            Ordering::Equal => continue,
            non_eq => return non_eq,
        }
    }
    Ordering::Equal
}

/// Is `version` within [start?, end?] with the given inclusivity? A missing
/// bound means unbounded on that side; both missing means "all versions".
pub fn version_in_range(
    version: &str,
    start: Option<&str>,
    start_incl: bool,
    end: Option<&str>,
    end_incl: bool,
) -> bool {
    if let Some(s) = start {
        match cmp_versions(version, s) {
            Ordering::Less => return false,
            Ordering::Equal if !start_incl => return false,
            _ => {}
        }
    }
    if let Some(e) = end {
        match cmp_versions(version, e) {
            Ordering::Greater => return false,
            Ordering::Equal if !end_incl => return false,
            _ => {}
        }
    }
    true
}

#[derive(Debug, Clone, Serialize)]
pub struct CveMatch {
    pub cve_id: String,
    pub product: String,
    pub cvss: Option<f64>,
    pub severity: Option<String>,
    pub summary: Option<String>,
    /// In the CISA KEV catalog — actively exploited in the wild.
    pub known_exploited: bool,
    /// KEV flags this CVE as used in known ransomware campaigns.
    pub ransomware: bool,
}

pub fn is_known_exploited(conn: &Connection, cve_id: &str) -> (bool, bool) {
    conn.query_row(
        "SELECT known_ransomware FROM kev WHERE cve_id = ?1",
        [cve_id],
        |r| r.get::<_, i64>(0),
    )
    .map(|rw| (true, rw != 0))
    .unwrap_or((false, false))
}

#[derive(Debug, Clone)]
pub struct CveRow {
    pub cve_id: String,
    pub vendor: String,
    pub product: String,
    pub version_start: Option<String>,
    pub version_start_incl: bool,
    pub version_end: Option<String>,
    pub version_end_incl: bool,
    pub cvss: Option<f64>,
    pub severity: Option<String>,
    pub summary: Option<String>,
}

pub fn insert_cve(conn: &Connection, c: &CveRow) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO cve (cve_id,vendor,product,version_start,version_start_incl,version_end,version_end_incl,cvss,severity,summary)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        rusqlite::params![
            c.cve_id, c.vendor, c.product.to_lowercase(),
            c.version_start, c.version_start_incl as i64,
            c.version_end, c.version_end_incl as i64,
            c.cvss, c.severity, c.summary
        ],
    )?;
    Ok(())
}

/// Match a detected product+version against the CVE store. Newest/most-severe
/// first. `product` is matched case-insensitively; nmap/CPE product names vary,
/// so callers should normalize (e.g. "Apache httpd" -> "http_server") upstream.
pub fn match_cves(conn: &Connection, product: &str, version: &str) -> rusqlite::Result<Vec<CveMatch>> {
    let mut stmt = conn.prepare(
        "SELECT cve_id,product,version_start,version_start_incl,version_end,version_end_incl,cvss,severity,summary
         FROM cve WHERE product = ?1",
    )?;
    let rows = stmt.query_map([product.to_lowercase()], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, i64>(3)? != 0,
            r.get::<_, Option<String>>(4)?,
            r.get::<_, i64>(5)? != 0,
            r.get::<_, Option<f64>>(6)?,
            r.get::<_, Option<String>>(7)?,
            r.get::<_, Option<String>>(8)?,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (cve_id, prod, vs, vsi, ve, vei, cvss, severity, summary) = row?;
        if version_in_range(version, vs.as_deref(), vsi, ve.as_deref(), vei) {
            let (known_exploited, ransomware) = is_known_exploited(conn, &cve_id);
            out.push(CveMatch { cve_id, product: prod, cvss, severity, summary, known_exploited, ransomware });
        }
    }
    // KEV (actively-exploited) first, then by CVSS descending.
    out.sort_by(|a, b| {
        b.known_exploited
            .cmp(&a.known_exploited)
            .then(b.cvss.unwrap_or(0.0).partial_cmp(&a.cvss.unwrap_or(0.0)).unwrap_or(Ordering::Equal))
    });
    Ok(out)
}

pub fn cve_count(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT COUNT(*) FROM cve", [], |r| r.get(0))
}

// ── Banner → CVE auto-detection ──────────────────────────────────────────────
// Turn a service banner (e.g. an HTTP `Server` header or nmap -sV product
// string) into CVE findings. Banner product names differ from CPE product
// names, so we normalize the common ones.

fn normalize_product(token: &str) -> Vec<String> {
    match token.to_lowercase().as_str() {
        "apache" | "httpd" | "apache-httpd" => vec!["http_server".into()],
        "nginx" => vec!["nginx".into()],
        "openssh" => vec!["openssh".into()],
        "openssl" => vec!["openssl".into()],
        "lighttpd" => vec!["lighttpd".into()],
        "microsoft-iis" | "iis" => vec!["internet_information_services".into()],
        "tomcat" | "apache-coyote" => vec!["tomcat".into()],
        "envoy" => vec!["envoy".into()],
        "uvicorn" => vec!["uvicorn".into()],
        "node" | "node.js" => vec!["node.js".into()],
        other => vec![other.to_string()],
    }
}

/// Extract candidate (product, version) pairs from a banner string. Handles
/// `Apache/2.4.49 (Unix)`, `nginx/1.25.2`, `OpenSSH_8.5`, `Microsoft-IIS/10.0`.
pub fn parse_banner(banner: &str) -> Vec<(String, String)> {
    use std::sync::OnceLock;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"([A-Za-z][A-Za-z\-.]*?)[/_ ]v?(\d+\.\d+(?:\.\d+)?[A-Za-z]?)").unwrap()
    });
    let mut out = Vec::new();
    for cap in re.captures_iter(banner) {
        let version = cap[2].to_string();
        for p in normalize_product(&cap[1]) {
            out.push((p, version.clone()));
        }
    }
    out
}

fn exploit_score(m: &CveMatch) -> u64 {
    if m.ransomware {
        return 95;
    }
    if m.known_exploited {
        return 90;
    }
    match m.cvss {
        Some(c) if c >= 9.0 => 80,
        Some(c) if c >= 7.0 => 65,
        Some(c) if c >= 4.0 => 45,
        _ => 30,
    }
}

/// Match a banner against the CVE store and produce Spectra finding payloads
/// (same shape the `scan-event` `finding` listener consumes). Deduped by CVE id.
pub fn banner_cve_findings(conn: &Connection, banner: &str, asset: &str) -> Vec<serde_json::Value> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (product, version) in parse_banner(banner) {
        for m in match_cves(conn, &product, &version).unwrap_or_default() {
            if !seen.insert(m.cve_id.clone()) {
                continue;
            }
            let mut tags = vec!["cve".to_string(), "sca".to_string()];
            if m.known_exploited {
                tags.push("kev".into());
            }
            if m.ransomware {
                tags.push("ransomware".into());
            }
            let recommendation = if m.known_exploited {
                "Actively exploited in the wild (CISA KEV) - patch immediately."
            } else {
                "Upgrade the affected component to a fixed version."
            };
            out.push(serde_json::json!({
                "source": "cve",
                "title": format!("{} in {} {}", m.cve_id, product, version),
                "severity": m.severity.clone().unwrap_or_else(|| "medium".into()),
                "asset": asset,
                "evidence": format!(
                    "Service banner '{} {}' matches {}{}",
                    product, version, m.cve_id,
                    if m.known_exploited { " - in CISA KEV (actively exploited)" } else { "" }
                ),
                "description": m.summary.clone().unwrap_or_default(),
                "recommendation": recommendation,
                "tags": tags,
                "cve": [m.cve_id],
                "exploitability": exploit_score(&m),
            }));
        }
    }
    out
}

// ── NVD import ───────────────────────────────────────────────────────────────
// Parses the NVD CVE API 2.0 / feed shape:
//   { "vulnerabilities": [ { "cve": { "id", "descriptions":[{lang,value}],
//     "metrics": { "cvssMetricV31|V30|V2": [{ "cvssData": { baseScore, baseSeverity }}] },
//     "configurations": [ { "nodes": [ { "cpeMatch": [
//       { "vulnerable": true, "criteria": "cpe:2.3:a:vendor:product:version:...",
//         "versionStartIncluding"|"versionStartExcluding"|"versionEndIncluding"|"versionEndExcluding" } ]}]}] }}]}

fn parse_cpe(criteria: &str) -> Option<(String, String, Option<String>)> {
    // cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
    let f: Vec<&str> = criteria.split(':').collect();
    if f.len() < 6 || f[0] != "cpe" {
        return None;
    }
    let vendor = f[3].to_string();
    let product = f[4].to_string();
    let version = match f[5] {
        "*" | "-" | "" => None,
        v => Some(v.to_string()),
    };
    Some((vendor, product, version))
}

fn extract_cvss(cve: &serde_json::Value) -> (Option<f64>, Option<String>) {
    let metrics = cve.get("metrics");
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
        if let Some(arr) = metrics.and_then(|m| m.get(key)).and_then(|v| v.as_array()) {
            if let Some(first) = arr.first().and_then(|m| m.get("cvssData")) {
                let score = first.get("baseScore").and_then(|s| s.as_f64());
                let sev = first
                    .get("baseSeverity")
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_lowercase())
                    .or_else(|| score.map(severity_from_score));
                return (score, sev);
            }
        }
    }
    (None, None)
}

fn severity_from_score(score: f64) -> String {
    match score {
        s if s >= 9.0 => "critical",
        s if s >= 7.0 => "high",
        s if s >= 4.0 => "medium",
        s if s > 0.0 => "low",
        _ => "info",
    }
    .to_string()
}

/// Import NVD JSON into the store, returning the number of (product,range) rows inserted.
pub fn import_nvd_json(conn: &mut Connection, json: &str) -> Result<usize, String> {
    let doc: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let vulns = doc
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .ok_or("missing 'vulnerabilities' array")?;

    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let mut inserted = 0usize;
    for entry in vulns {
        let cve = match entry.get("cve") {
            Some(c) => c,
            None => continue,
        };
        let cve_id = cve.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if cve_id.is_empty() {
            continue;
        }
        let summary = cve
            .get("descriptions")
            .and_then(|d| d.as_array())
            .and_then(|arr| arr.iter().find(|d| d.get("lang").and_then(|l| l.as_str()) == Some("en")))
            .and_then(|d| d.get("value"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let (cvss, severity) = extract_cvss(cve);

        let configs = cve.get("configurations").and_then(|c| c.as_array());
        if let Some(configs) = configs {
            for cfg in configs {
                let nodes = cfg.get("nodes").and_then(|n| n.as_array());
                if let Some(nodes) = nodes {
                    for node in nodes {
                        if let Some(matches) = node.get("cpeMatch").and_then(|m| m.as_array()) {
                            for m in matches {
                                if m.get("vulnerable").and_then(|v| v.as_bool()) != Some(true) {
                                    continue;
                                }
                                let criteria = match m.get("criteria").and_then(|c| c.as_str()) {
                                    Some(c) => c,
                                    None => continue,
                                };
                                // Only application/OS CPEs (a / o), skip hardware.
                                let part = criteria.split(':').nth(2).unwrap_or("");
                                if part != "a" && part != "o" {
                                    continue;
                                }
                                let (vendor, product, exact) = match parse_cpe(criteria) {
                                    Some(p) => p,
                                    None => continue,
                                };
                                let g = |k: &str| m.get(k).and_then(|v| v.as_str()).map(|s| s.to_string());
                                // Range fields take precedence; otherwise an exact-version CPE.
                                let (mut vs, mut vsi) = (g("versionStartIncluding"), true);
                                if vs.is_none() {
                                    if let Some(v) = g("versionStartExcluding") {
                                        vs = Some(v);
                                        vsi = false;
                                    }
                                }
                                let (mut ve, mut vei) = (g("versionEndIncluding"), true);
                                if ve.is_none() {
                                    if let Some(v) = g("versionEndExcluding") {
                                        ve = Some(v);
                                        vei = false;
                                    }
                                }
                                if vs.is_none() && ve.is_none() {
                                    // No range -> use the exact version from the CPE (if any).
                                    if let Some(v) = exact {
                                        vs = Some(v.clone());
                                        ve = Some(v);
                                        vsi = true;
                                        vei = true;
                                    }
                                    // else: all versions of the product are vulnerable.
                                }
                                let row = CveRow {
                                    cve_id: cve_id.clone(),
                                    vendor,
                                    product,
                                    version_start: vs,
                                    version_start_incl: vsi,
                                    version_end: ve,
                                    version_end_incl: vei,
                                    cvss,
                                    severity: severity.clone(),
                                    summary: summary.clone(),
                                };
                                tx.execute(
                                    "INSERT INTO cve (cve_id,vendor,product,version_start,version_start_incl,version_end,version_end_incl,cvss,severity,summary)
                                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                                    rusqlite::params![
                                        row.cve_id, row.vendor, row.product.to_lowercase(),
                                        row.version_start, row.version_start_incl as i64,
                                        row.version_end, row.version_end_incl as i64,
                                        row.cvss, row.severity, row.summary
                                    ],
                                ).map_err(|e| e.to_string())?;
                                inserted += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(inserted)
}

// ── CISA KEV import ──────────────────────────────────────────────────────────
// Parses the CISA Known Exploited Vulnerabilities catalog:
//   { "vulnerabilities": [ { "cveID", "vendorProject", "product",
//     "vulnerabilityName", "dateAdded", "dueDate", "shortDescription",
//     "knownRansomwareCampaignUse": "Known"|"Unknown" } ] }

pub fn import_kev_json(conn: &mut Connection, json: &str) -> Result<usize, String> {
    let doc: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let vulns = doc
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .ok_or("missing 'vulnerabilities' array")?;

    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let mut n = 0usize;
    for v in vulns {
        let id = match v.get("cveID").and_then(|x| x.as_str()) {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };
        let g = |k: &str| v.get(k).and_then(|x| x.as_str());
        let ransomware = g("knownRansomwareCampaignUse").map(|s| s.eq_ignore_ascii_case("known")).unwrap_or(false);
        tx.execute(
            "INSERT OR REPLACE INTO kev (cve_id,vendor_project,product,vuln_name,date_added,due_date,known_ransomware,short_description)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            rusqlite::params![
                id, g("vendorProject"), g("product"), g("vulnerabilityName"),
                g("dateAdded"), g("dueDate"), ransomware as i64, g("shortDescription")
            ],
        )
        .map_err(|e| e.to_string())?;
        n += 1;
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(n)
}

pub fn kev_count(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT COUNT(*) FROM kev", [], |r| r.get(0))
}

/// Seed a small set of well-known CVEs so matching works out of the box before
/// a full NVD feed is imported.
pub fn seed_known_cves(conn: &mut Connection) -> rusqlite::Result<()> {
    if cve_count(conn)? > 0 {
        return Ok(());
    }
    let seed = [
        CveRow { cve_id: "CVE-2021-41773".into(), vendor: "apache".into(), product: "http_server".into(),
            version_start: Some("2.4.49".into()), version_start_incl: true, version_end: Some("2.4.49".into()), version_end_incl: true,
            cvss: Some(7.5), severity: Some("high".into()), summary: Some("Path traversal & RCE in Apache HTTP Server 2.4.49 (mod_cgi).".into()) },
        CveRow { cve_id: "CVE-2021-42013".into(), vendor: "apache".into(), product: "http_server".into(),
            version_start: Some("2.4.49".into()), version_start_incl: true, version_end: Some("2.4.50".into()), version_end_incl: true,
            cvss: Some(9.8), severity: Some("critical".into()), summary: Some("Path traversal & RCE in Apache HTTP Server 2.4.49/2.4.50 (incomplete fix).".into()) },
        CveRow { cve_id: "CVE-2014-0160".into(), vendor: "openssl".into(), product: "openssl".into(),
            version_start: Some("1.0.1".into()), version_start_incl: true, version_end: Some("1.0.1f".into()), version_end_incl: true,
            cvss: Some(7.5), severity: Some("high".into()), summary: Some("Heartbleed — TLS heartbeat read overrun discloses memory.".into()) },
        CveRow { cve_id: "CVE-2024-6387".into(), vendor: "openbsd".into(), product: "openssh".into(),
            version_start: Some("8.5".into()), version_start_incl: true, version_end: Some("9.8".into()), version_end_incl: false,
            cvss: Some(8.1), severity: Some("high".into()), summary: Some("regreSSHion — signal-handler race in OpenSSH sshd allows RCE.".into()) },
        CveRow { cve_id: "CVE-2023-44487".into(), vendor: "nginx".into(), product: "nginx".into(),
            version_start: None, version_start_incl: true, version_end: Some("1.25.3".into()), version_end_incl: false,
            cvss: Some(7.5), severity: Some("high".into()), summary: Some("HTTP/2 Rapid Reset DoS.".into()) },
    ];
    for row in &seed {
        insert_cve(conn, row)?;
    }
    // All five seeded CVEs are in the real CISA KEV catalog — seed them so the
    // out-of-box "known exploited" flag works before a live KEV feed is imported.
    let kev = [
        ("CVE-2021-41773", "Apache", "HTTP Server", false),
        ("CVE-2021-42013", "Apache", "HTTP Server", false),
        ("CVE-2014-0160", "OpenSSL", "OpenSSL", false),
        ("CVE-2024-6387", "OpenBSD", "OpenSSH", false),
        ("CVE-2023-44487", "Multiple", "HTTP/2", false),
    ];
    for (id, vp, prod, ransom) in kev {
        conn.execute(
            "INSERT OR REPLACE INTO kev (cve_id,vendor_project,product,known_ransomware) VALUES (?1,?2,?3,?4)",
            rusqlite::params![id, vp, prod, ransom as i64],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_cve_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn version_comparison() {
        assert_eq!(cmp_versions("2.4.49", "2.4.50"), Ordering::Less);
        assert_eq!(cmp_versions("2.4.50", "2.4.49"), Ordering::Greater);
        assert_eq!(cmp_versions("2.4.49", "2.4.49"), Ordering::Equal);
        assert_eq!(cmp_versions("1.0", "1.0.0"), Ordering::Equal); // zero-pad
        assert_eq!(cmp_versions("1.10", "1.9"), Ordering::Greater); // numeric, not lexical
        assert_eq!(cmp_versions("9.8", "9.10"), Ordering::Less);
        assert_eq!(cmp_versions("2.4.49a", "2.4.49"), Ordering::Equal); // suffix dropped
    }

    #[test]
    fn range_inclusivity() {
        assert!(version_in_range("2.4.49", Some("2.4.49"), true, Some("2.4.50"), false));
        assert!(!version_in_range("2.4.50", Some("2.4.49"), true, Some("2.4.50"), false)); // end excluded
        assert!(version_in_range("2.4.50", Some("2.4.49"), true, Some("2.4.50"), true)); // end included
        assert!(!version_in_range("2.4.48", Some("2.4.49"), true, None, false)); // below start
        assert!(version_in_range("99.0", None, true, None, false)); // unbounded both sides
        assert!(version_in_range("1.0.0", None, true, Some("1.25.3"), false)); // only upper bound
    }

    #[test]
    fn seed_and_match_apache() {
        let mut conn = mem();
        seed_known_cves(&mut conn).unwrap();
        let m = match_cves(&conn, "http_server", "2.4.49").unwrap();
        let ids: Vec<_> = m.iter().map(|c| c.cve_id.as_str()).collect();
        assert!(ids.contains(&"CVE-2021-41773"));
        assert!(ids.contains(&"CVE-2021-42013"));
        // sorted by CVSS desc -> the 9.8 critical comes first
        assert_eq!(m[0].cve_id, "CVE-2021-42013");
        // a patched version matches neither
        assert!(match_cves(&conn, "http_server", "2.4.58").unwrap().is_empty());
    }

    #[test]
    fn match_is_case_insensitive_on_product() {
        let mut conn = mem();
        seed_known_cves(&mut conn).unwrap();
        assert!(!match_cves(&conn, "OpenSSL", "1.0.1f").unwrap().is_empty());
    }

    #[test]
    fn nginx_unbounded_lower_then_fixed() {
        let mut conn = mem();
        seed_known_cves(&mut conn).unwrap();
        assert!(!match_cves(&conn, "nginx", "1.25.2").unwrap().is_empty()); // below fix -> vuln
        assert!(match_cves(&conn, "nginx", "1.25.3").unwrap().is_empty()); // fixed
    }

    #[test]
    fn imports_nvd_json() {
        let json = r#"{
          "vulnerabilities": [
            { "cve": {
                "id": "CVE-2099-0001",
                "descriptions": [{"lang":"en","value":"Test flaw in widget."}],
                "metrics": { "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}] },
                "configurations": [ { "nodes": [ { "cpeMatch": [
                  { "vulnerable": true, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
                    "versionStartIncluding": "1.0", "versionEndExcluding": "1.5" }
                ] } ] } ]
            } }
          ]
        }"#;
        let mut conn = mem();
        let n = import_nvd_json(&mut conn, json).unwrap();
        assert_eq!(n, 1);
        let m = match_cves(&conn, "widget", "1.2").unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].cve_id, "CVE-2099-0001");
        assert_eq!(m[0].severity.as_deref(), Some("critical"));
        assert!(match_cves(&conn, "widget", "1.5").unwrap().is_empty()); // end excluded
        assert!(match_cves(&conn, "widget", "0.9").unwrap().is_empty()); // below start
    }

    #[test]
    fn seeded_cves_are_flagged_known_exploited() {
        let mut conn = mem();
        seed_known_cves(&mut conn).unwrap();
        assert_eq!(kev_count(&conn).unwrap(), 5);
        let m = match_cves(&conn, "http_server", "2.4.49").unwrap();
        assert!(m.iter().all(|c| c.known_exploited)); // both Apache CVEs are in KEV
    }

    #[test]
    fn parses_banners_into_product_version() {
        assert_eq!(parse_banner("Apache/2.4.49 (Unix)"), vec![("http_server".into(), "2.4.49".into())]);
        assert_eq!(parse_banner("nginx/1.25.2"), vec![("nginx".into(), "1.25.2".into())]);
        assert_eq!(parse_banner("SSH-2.0-OpenSSH_8.5"), vec![("openssh".into(), "8.5".into())]);
        assert_eq!(parse_banner("Microsoft-IIS/10.0"), vec![("internet_information_services".into(), "10.0".into())]);
        assert!(parse_banner("uvicorn").is_empty()); // no version -> no match
    }

    #[test]
    fn banner_findings_carry_kev_and_boosted_exploitability() {
        let mut conn = mem();
        seed_known_cves(&mut conn).unwrap();
        let f = banner_cve_findings(&conn, "Apache/2.4.49 (Unix)", "10.0.0.1:443");
        assert_eq!(f.len(), 2); // CVE-2021-41773 + CVE-2021-42013, deduped
        let top = &f[0];
        assert_eq!(top["source"], "cve");
        assert_eq!(top["asset"], "10.0.0.1:443");
        let tags: Vec<&str> = top["tags"].as_array().unwrap().iter().map(|t| t.as_str().unwrap()).collect();
        assert!(tags.contains(&"kev"));
        assert_eq!(top["exploitability"], 90); // KEV boost
    }

    #[test]
    fn banner_no_match_for_patched_version() {
        let mut conn = mem();
        seed_known_cves(&mut conn).unwrap();
        assert!(banner_cve_findings(&conn, "Apache/2.4.58", "h").is_empty());
    }

    #[test]
    fn kev_import_flags_matches_including_ransomware() {
        let mut conn = mem();
        import_nvd_json(
            &mut conn,
            r#"{"vulnerabilities":[{"cve":{"id":"CVE-2099-9",
              "descriptions":[{"lang":"en","value":"x"}],
              "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]},
              "configurations":[{"nodes":[{"cpeMatch":[
                {"vulnerable":true,"criteria":"cpe:2.3:a:acme:thing:1.0:*:*:*:*:*:*:*"}]}]}]}}]}"#,
        )
        .unwrap();
        // Not yet in KEV.
        assert!(!match_cves(&conn, "thing", "1.0").unwrap()[0].known_exploited);
        // Import KEV listing it as ransomware-used.
        let n = import_kev_json(
            &mut conn,
            r#"{"vulnerabilities":[{"cveID":"CVE-2099-9","vendorProject":"ACME","product":"Thing","knownRansomwareCampaignUse":"Known"}]}"#,
        )
        .unwrap();
        assert_eq!(n, 1);
        let m = match_cves(&conn, "thing", "1.0").unwrap();
        assert!(m[0].known_exploited);
        assert!(m[0].ransomware);
    }
}
