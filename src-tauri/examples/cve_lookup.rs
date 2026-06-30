//! Look up CVEs (with CISA KEV "actively exploited" flags) for a detected
//! product + version, using Spectra's offline CVE engine.
//!
//!   cargo run --example cve_lookup                       # http_server 2.4.49
//!   cargo run --example cve_lookup -- <product> <version>
//!   cargo run --example cve_lookup -- openssl 1.0.1f

use app_lib::vuln_db::{cve_count, init_cve_schema, kev_count, match_cves, seed_known_cves};
use rusqlite::Connection;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let product = args.get(1).cloned().unwrap_or_else(|| "http_server".into());
    let version = args.get(2).cloned().unwrap_or_else(|| "2.4.49".into());

    let mut conn = Connection::open_in_memory().unwrap();
    init_cve_schema(&conn).unwrap();
    seed_known_cves(&mut conn).unwrap();

    println!(
        "Spectra CVE engine - {} CVE rows, {} KEV entries (seed)\n",
        cve_count(&conn).unwrap(),
        kev_count(&conn).unwrap()
    );
    println!("Matching {product} {version}\n");

    let matches = match_cves(&conn, &product, &version).unwrap();
    if matches.is_empty() {
        println!("  (no known CVEs for that product/version)");
        return;
    }
    for m in matches {
        let tag = match (m.known_exploited, m.ransomware) {
            (true, true) => "  [KEV + RANSOMWARE]",
            (true, false) => "  [KEV - actively exploited]",
            _ => "",
        };
        println!(
            "  {}  CVSS {:<4} {:<9}{}",
            m.cve_id,
            m.cvss.map(|c| c.to_string()).unwrap_or_else(|| "-".into()),
            m.severity.as_deref().unwrap_or("-"),
            tag
        );
        if let Some(s) = m.summary {
            println!("      {s}");
        }
    }
}
