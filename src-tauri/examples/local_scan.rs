//! Run Spectra's scan-engine logic against a host from the CLI.
//! Mirrors src/lib.rs `tcp_port_scan` (semaphore-bounded pure-Rust TCP connect
//! scan) + `http_probe` (reqwest banner/header probe) — the same approach the
//! desktop app's native engine uses, but runnable headlessly.
//!
//!   cargo run --example local_scan            # scans 127.0.0.1
//!   cargo run --example local_scan -- <host>

use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

fn guess_service(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "domain",
        80 => "http",
        110 => "pop3",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        443 => "https",
        445 => "smb",
        808 => "http-alt",
        3306 => "mysql",
        3389 => "rdp",
        5040 => "rpc",
        5173 => "http-dev",
        5432 => "postgres",
        5900 => "vnc",
        6379 => "redis",
        8000 | 8080 | 8005 => "http-alt",
        8443 => "https-alt",
        9993 => "zerotier",
        11434 => "ollama",
        27017 => "mongodb",
        _ => "unknown",
    }
}

/// Network-exposed services worth flagging on a finding report.
fn risk_note(port: u16) -> Option<&'static str> {
    match port {
        445 => Some("SMB exposed — ensure SMBv1 disabled, signing enforced, not reachable off-host"),
        139 => Some("NetBIOS session service exposed — legacy, restrict to trusted segments"),
        135 => Some("MSRPC endpoint mapper exposed — restrict via firewall"),
        23 => Some("Telnet — cleartext protocol, disable in favour of SSH"),
        21 => Some("FTP — often cleartext, prefer SFTP/FTPS"),
        3389 => Some("RDP exposed — enforce NLA + MFA, restrict source IPs"),
        6379 => Some("Redis exposed — ensure auth + bind to loopback"),
        11434 => Some("Ollama API exposed — bind to loopback only; do not expose on LAN"),
        _ => None,
    }
}

fn is_web(port: u16) -> bool {
    matches!(guess_service(port), "http" | "https" | "http-alt" | "https-alt" | "http-dev" | "ollama")
}

#[tokio::main]
async fn main() {
    let host = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1".to_string());
    let ports: Vec<u16> = vec![
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 808, 993, 995, 1433, 3306, 3389, 5040,
        5173, 5432, 5900, 6379, 8000, 8005, 8080, 8443, 9000, 9993, 11434, 27017, 28385, 28390,
    ];

    println!("Spectra engine · TCP connect scan of {host} ({} ports)\n", ports.len());

    let sem = Arc::new(Semaphore::new(80));
    let mut tasks = Vec::new();
    for port in ports {
        let sem = sem.clone();
        let host = host.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let addr = format!("{host}:{port}");
            let start = std::time::Instant::now();
            let open = matches!(
                tokio::time::timeout(Duration::from_millis(800), TcpStream::connect(&addr)).await,
                Ok(Ok(_))
            );
            open.then(|| (port, start.elapsed().as_millis()))
        }));
    }

    let mut open = Vec::new();
    for t in tasks {
        if let Ok(Some(p)) = t.await {
            open.push(p);
        }
    }
    open.sort();

    if open.is_empty() {
        println!("No open ports found.");
        return;
    }

    println!("OPEN PORTS ({})", open.len());
    for (port, lat) in &open {
        println!("  {port:>5}/tcp  open   {:<13} ({lat} ms)", guess_service(*port));
    }

    // HTTP probe — mirrors http_probe (reqwest, accepts invalid certs for scanning).
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(6))
        .user_agent("Spectra/0.1")
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let web: Vec<u16> = open.iter().map(|(p, _)| *p).filter(|p| is_web(*p)).collect();
    if !web.is_empty() {
        println!("\nHTTP PROBES");
        for port in web {
            let scheme = if matches!(port, 443 | 8443) { "https" } else { "http" };
            let url = format!("{scheme}://{host}:{port}");
            match client.get(&url).send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let server = resp.headers().get("server").and_then(|v| v.to_str().ok()).unwrap_or("-");
                    let powered =
                        resp.headers().get("x-powered-by").and_then(|v| v.to_str().ok()).unwrap_or("-");
                    println!("  {url:<28} → HTTP {status}  server={server}  x-powered-by={powered}");
                }
                Err(_) => println!("  {url:<28} → no HTTP response"),
            }
        }
    }

    let notes: Vec<_> = open.iter().filter_map(|(p, _)| risk_note(*p).map(|n| (*p, n))).collect();
    if !notes.is_empty() {
        println!("\nNOTABLE (advisory findings)");
        for (port, note) in notes {
            println!("  [{}] {note}", guess_service(port));
        }
    }
}
