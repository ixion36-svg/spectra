//! Authenticated-scan analysis demo: match an installed-package list against
//! Spectra's CVE engine (with CISA KEV flags).
//!
//!   cargo run --example pkg_scan

use app_lib::auth_scan::{package_cve_findings, parse_packages, PkgFormat};
use app_lib::vuln_db::{init_cve_schema, seed_known_cves};
use rusqlite::Connection;

fn main() {
    // A sample `dpkg -l` excerpt from a stale host.
    let dpkg = "\
ii  openssl          1.0.1f-1ubuntu2   amd64  Secure Sockets Layer toolkit
ii  openssh-server   8.5p1-1           amd64  secure shell (SSH) server
ii  apache2          2.4.49-1          amd64  Apache HTTP Server
ii  bash             5.0-6ubuntu1      amd64  GNU Bourne Again SHell
";

    let mut conn = Connection::open_in_memory().unwrap();
    init_cve_schema(&conn).unwrap();
    seed_known_cves(&mut conn).unwrap();

    let pkgs = parse_packages(dpkg, PkgFormat::Dpkg);
    println!("Parsed {} packages from dpkg output\n", pkgs.len());

    let findings = package_cve_findings(&conn, &pkgs, "10.0.0.9");
    if findings.is_empty() {
        println!("No CVEs matched.");
        return;
    }
    println!("CVE findings ({}):", findings.len());
    for f in findings {
        let kev = f["tags"].as_array().map(|t| t.iter().any(|x| x == "kev")).unwrap_or(false);
        println!(
            "  {}  {:<9} exploit={:<3}{}  {}",
            f["cve"][0].as_str().unwrap_or("?"),
            f["severity"].as_str().unwrap_or("-"),
            f["exploitability"].as_u64().unwrap_or(0),
            if kev { "  [KEV]" } else { "" },
            f["title"].as_str().unwrap_or("")
        );
    }
}
