//! Authenticated-scan analysis core: turn a host's installed-package list into
//! CVE findings. This is the analytical half of credentialed scanning — the SSH
//! transport that collects the package list lives separately. Parsing is pure
//! and unit-tested; matching reuses the CVE engine.

use crate::vuln_db;
use rusqlite::Connection;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PkgFormat {
    /// `dpkg -l` output (Debian/Ubuntu).
    Dpkg,
    /// `rpm -qa` output (RHEL/Fedora/SUSE).
    Rpm,
    /// One `name version` (or `name/version`) per line.
    Generic,
}

impl PkgFormat {
    pub fn from_str(s: &str) -> PkgFormat {
        match s.to_lowercase().as_str() {
            "dpkg" | "deb" => PkgFormat::Dpkg,
            "rpm" => PkgFormat::Rpm,
            _ => PkgFormat::Generic,
        }
    }
}

/// Strip a Debian/RPM epoch + release so we keep the upstream version
/// (`1:1.1.1f-1ubuntu2` -> `1.1.1f`, `1.1.1k-7.el8` -> `1.1.1k`).
fn upstream_version(v: &str) -> String {
    let no_epoch = v.split_once(':').map(|(_, rest)| rest).unwrap_or(v);
    no_epoch.split('-').next().unwrap_or(no_epoch).to_string()
}

/// Parse package-manager output into (name, version) pairs.
pub fn parse_packages(text: &str, format: PkgFormat) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match format {
            PkgFormat::Dpkg => {
                // ii  openssl  1.1.1f-1ubuntu2.20  amd64  Secure Sockets Layer ...
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() >= 3 && cols[0].starts_with("ii") {
                    let name = cols[1].split(':').next().unwrap_or(cols[1]); // drop :amd64 arch suffix
                    out.push((name.to_string(), upstream_version(cols[2])));
                }
            }
            PkgFormat::Rpm => {
                // NEVRA: name-version-release.arch (name may contain hyphens). The
                // release is after the last '-', the version between the last two.
                let stripped = line.rsplit_once('.').map(|(p, _)| p).unwrap_or(line); // drop .arch
                if let Some(rel_dash) = stripped.rfind('-') {
                    let before_rel = &stripped[..rel_dash];
                    if let Some(ver_dash) = before_rel.rfind('-') {
                        let name = &before_rel[..ver_dash];
                        let version = &before_rel[ver_dash + 1..];
                        if version.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                            out.push((name.to_string(), upstream_version(version)));
                        }
                    }
                }
            }
            PkgFormat::Generic => {
                // "name version" or "name/version" or "name version arch"
                let (name, ver) = if let Some((n, v)) = line.split_once('/') {
                    (n.trim(), v.split_whitespace().next().unwrap_or("").trim())
                } else {
                    let cols: Vec<&str> = line.split_whitespace().collect();
                    if cols.len() < 2 {
                        continue;
                    }
                    (cols[0], cols[1])
                };
                if !name.is_empty() && ver.chars().any(|c| c.is_ascii_digit()) {
                    out.push((name.to_string(), upstream_version(ver)));
                }
            }
        }
    }
    out
}

// ── SSH transport (key-based, via the system ssh client) ─────────────────────
// Spectra shells out to the OS `ssh` (built into Windows/macOS/Linux) rather
// than bundling an SSH library: no extra dependency, the hardened system client,
// and BatchMode so it never blocks on a prompt. v1 is key-based auth.

/// Remote command that prints the installed-package list on Debian or RHEL hosts.
pub const ENUM_COMMAND: &str = "dpkg -l 2>/dev/null || rpm -qa 2>/dev/null";

/// Build the argv for `ssh` to run `command` on a host with key-based auth.
pub fn build_ssh_args(host: &str, port: u16, user: &str, key_path: Option<&str>, command: &str) -> Vec<String> {
    let mut a = vec![
        "-o".into(), "BatchMode=yes".into(), // never prompt; fail instead of hanging
        "-o".into(), "StrictHostKeyChecking=accept-new".into(),
        "-o".into(), "ConnectTimeout=10".into(),
        "-p".into(), port.to_string(),
    ];
    if let Some(k) = key_path {
        if !k.is_empty() {
            a.push("-i".into());
            a.push(k.to_string());
        }
    }
    a.push(format!("{}@{}", user, host));
    a.push(command.to_string());
    a
}

/// Guess the package format from the enumeration output.
pub fn detect_format(output: &str) -> PkgFormat {
    if output.lines().any(|l| {
        let t = l.trim_start();
        t.starts_with("ii ") || t.starts_with("Desired=") || t.starts_with("rc ")
    }) {
        PkgFormat::Dpkg
    } else if output.lines().any(|l| {
        let l = l.trim();
        (l.ends_with(".x86_64") || l.ends_with(".noarch") || l.ends_with(".aarch64") || l.contains(".el"))
            && l.matches('-').count() >= 2
    }) {
        PkgFormat::Rpm
    } else {
        PkgFormat::Generic
    }
}

/// Match every parsed package against the CVE store, returning finding payloads
/// (deduped by CVE id across packages).
pub fn package_cve_findings(conn: &Connection, packages: &[(String, String)], asset: &str) -> Vec<serde_json::Value> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (name, version) in packages {
        for f in vuln_db::cve_findings_for(conn, name, version, asset) {
            let id = f.get("cve").and_then(|c| c.get(0)).and_then(|v| v.as_str()).unwrap_or("").to_string();
            if seen.insert(id) {
                out.push(f);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vuln_db::{init_cve_schema, seed_known_cves};

    fn db() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        init_cve_schema(&conn).unwrap();
        seed_known_cves(&mut conn).unwrap();
        conn
    }

    #[test]
    fn parses_dpkg() {
        let text = "Desired=Unknown/Install...\n\
            ii  openssl  1.0.1f-1ubuntu2  amd64  Secure Sockets Layer toolkit\n\
            ii  openssh-server:amd64  8.5p1-1  amd64  secure shell server\n\
            rc  removed-pkg  1.0  amd64  leftover config\n";
        let pkgs = parse_packages(text, PkgFormat::Dpkg);
        assert!(pkgs.contains(&("openssl".into(), "1.0.1f".into())));
        assert!(pkgs.contains(&("openssh-server".into(), "8.5p1".into())));
        assert!(!pkgs.iter().any(|(n, _)| n == "removed-pkg")); // rc (not ii) skipped
    }

    #[test]
    fn parses_rpm() {
        let pkgs = parse_packages("openssl-1.0.1f-7.el7.x86_64\nhttpd-2.4.49-1.fc34.x86_64\n", PkgFormat::Rpm);
        assert!(pkgs.contains(&("openssl".into(), "1.0.1f".into())));
        assert!(pkgs.contains(&("httpd".into(), "2.4.49".into())));
    }

    #[test]
    fn parses_generic() {
        let pkgs = parse_packages("nginx 1.25.2\nopenssl/1.0.1f\nbash\n", PkgFormat::Generic);
        assert!(pkgs.contains(&("nginx".into(), "1.25.2".into())));
        assert!(pkgs.contains(&("openssl".into(), "1.0.1f".into())));
        assert!(!pkgs.iter().any(|(n, _)| n == "bash")); // no version -> skipped
    }

    #[test]
    fn package_findings_match_cves_with_normalization() {
        let conn = db();
        // dpkg "openssh-server" + "openssl" + "apache2" map to CPE products.
        let text = "ii  openssl  1.0.1f-1  amd64  ssl\n\
            ii  openssh-server  8.5p1-1  amd64  ssh\n\
            ii  apache2  2.4.49-1  amd64  web\n";
        let pkgs = parse_packages(text, PkgFormat::Dpkg);
        let findings = package_cve_findings(&conn, &pkgs, "10.0.0.9");
        let cves: Vec<String> = findings
            .iter()
            .filter_map(|f| f["cve"][0].as_str().map(|s| s.to_string()))
            .collect();
        assert!(cves.contains(&"CVE-2014-0160".to_string())); // openssl heartbleed
        assert!(cves.contains(&"CVE-2024-6387".to_string())); // openssh regreSSHion (8.5 in range)
        assert!(cves.contains(&"CVE-2021-41773".to_string())); // apache2 -> http_server 2.4.49
        // all are KEV-flagged
        assert!(findings.iter().all(|f| f["tags"].as_array().unwrap().iter().any(|t| t == "kev")));
    }

    #[test]
    fn builds_ssh_args_keybased_and_safe() {
        let a = build_ssh_args("10.0.0.5", 2222, "scanner", Some("/keys/id_ed25519"), ENUM_COMMAND);
        assert!(a.windows(2).any(|w| w == ["-o", "BatchMode=yes"])); // never hang on a prompt
        assert!(a.windows(2).any(|w| w == ["-p", "2222"]));
        assert!(a.windows(2).any(|w| w == ["-i", "/keys/id_ed25519"]));
        assert!(a.contains(&"scanner@10.0.0.5".to_string()));
        assert_eq!(a.last().unwrap(), ENUM_COMMAND);
        // no key -> no -i
        let b = build_ssh_args("h", 22, "u", None, "x");
        assert!(!b.iter().any(|s| s == "-i"));
    }

    #[test]
    fn detects_package_format() {
        assert_eq!(detect_format("Desired=Unknown\nii  openssl  1.0.1f  amd64"), PkgFormat::Dpkg);
        assert_eq!(detect_format("openssl-1.0.1f-7.el7.x86_64\nbash-5.0-1.el7.x86_64"), PkgFormat::Rpm);
        assert_eq!(detect_format("nginx 1.25.2\nopenssl 1.0.1f"), PkgFormat::Generic);
    }

    #[test]
    fn upstream_version_strips_epoch_and_release() {
        assert_eq!(upstream_version("1:1.1.1f-1ubuntu2"), "1.1.1f");
        assert_eq!(upstream_version("1.1.1k-7.el8"), "1.1.1k");
        assert_eq!(upstream_version("2.4.49"), "2.4.49");
    }
}
