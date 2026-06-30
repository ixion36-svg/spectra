use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Stdio;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tauri::ipc::Channel;
use tauri::{Emitter, Manager};

mod plugins;
pub mod vuln_db;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command as TokioCommand;
use tokio::time::Duration;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ToolStatus {
    pub name: String,
    pub available: bool,
    pub path: Option<String>,
    pub version: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ScanEvent {
    pub scan_id: String,
    pub event_type: String, // "log" | "finding" | "progress" | "complete" | "error"
    pub data: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ExternalScanResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
}

/// Shared state to track running external scan processes for cancellation.
#[derive(Default)]
struct RunningScans {
    pids: Mutex<HashMap<String, Vec<u32>>>,
}

/// SQLite-backed scan store. The connection is synchronous, so it lives behind a
/// Mutex; commands lock it briefly with no await held across the guard.
struct Db(Mutex<rusqlite::Connection>);

#[tauri::command]
async fn detect_installed_tools(app: tauri::AppHandle) -> Result<Vec<ToolStatus>, String> {
    let tools = vec!["nmap", "nuclei", "trivy", "osv-scanner"];
    let mut results = Vec::new();

    for tool in tools {
        // Use shell plugin sidecar detection + direct which
        let (available, path, version) = match tool {
            "nuclei" => check_tool("nuclei", vec!["-version"]).await,
            "trivy" => check_tool("trivy", vec!["version"]).await,
            "nmap" => check_tool("nmap", vec!["-V"]).await,
            "osv-scanner" => check_tool("osv-scanner", vec!["--version"]).await,
            _ => (false, None, None),
        };

        results.push(ToolStatus {
            name: tool.to_string(),
            available,
            path,
            version,
        });
    }

    // Also try to emit for the frontend
    let _ = app.emit("tools-detected", &results);
    Ok(results)
}

async fn check_tool(name: &str, version_args: Vec<&str>) -> (bool, Option<String>, Option<String>) {
    // Try direct command first (respects user PATH including the ~\bin\nuclei we added)
    if let Ok(output) = TokioCommand::new(name)
        .args(&version_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
    {
        if output.status.success() || !output.stdout.is_empty() {
            let stdout_str = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr_str = String::from_utf8_lossy(&output.stderr).to_string();
            let version = stdout_str
                .lines()
                .next()
                .or_else(|| stderr_str.lines().next())
                .map(|s| s.trim().to_string());
            return (true, Some(name.to_string()), version);
        }
    }

    // Fallback: try common Windows locations + our custom bin + winget packages
    let user = std::env::var("USERPROFILE").unwrap_or_default();
    let mut candidates: Vec<String> = vec![
        format!(r"{}\bin\{}\{}.exe", user, name, name),
        format!(r"C:\Program Files\{}\{}.exe", name, name),
        format!(r"C:\Program Files (x86)\{}\{}.exe", name, name),
    ];
    // WinGet locations (common for trivy/nmap)
    let winget_base = format!(r"{}\AppData\Local\Microsoft\WinGet\Packages", user);
    if let Ok(entries) = std::fs::read_dir(&winget_base) {
        for entry in entries.filter_map(|e| e.ok()) {
            let dir_name = entry.file_name().to_string_lossy().to_lowercase();
            if dir_name.contains(&name.to_lowercase()) {
                let exe_path = entry.path().join(format!("{}.exe", name));
                if exe_path.exists() {
                    candidates.push(exe_path.to_string_lossy().to_string());
                }
                // sometimes in subdir
                if let Ok(subs) = std::fs::read_dir(entry.path()) {
                    for sub in subs.filter_map(|e| e.ok()) {
                        let sub_exe = sub.path().join(format!("{}.exe", name));
                        if sub_exe.exists() {
                            candidates.push(sub_exe.to_string_lossy().to_string());
                        }
                    }
                }
            }
        }
    }

    for candidate in candidates {
        let p = PathBuf::from(&candidate);
        if p.exists() {
            if let Ok(output) = TokioCommand::new(&p)
                .args(&version_args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await
            {
                let stdout_str = String::from_utf8_lossy(&output.stdout).to_string();
                let version = stdout_str.lines().next().map(|s| s.trim().to_string());
                return (true, Some(candidate), version);
            }
        }
    }

    (false, None, None)
}

#[tauri::command]
async fn run_external_scan(
    app: tauri::AppHandle,
    scan_id: String,
    tool: String,
    target: String,
    extra_args: Vec<String>,
    state: tauri::State<'_, RunningScans>,
) -> Result<ExternalScanResult, String> {
    let start = std::time::Instant::now();

    // Reject flag-like / malformed targets before they reach an external tool.
    validate_target(&target)?;

    // Resolve the binary (prefer direct name so PATH including user additions works)
    let binary = match tool.as_str() {
        "nuclei" => "nuclei",
        "trivy" => "trivy",
        "nmap" => "nmap",
        "osv-scanner" => "osv-scanner",
        _ => &tool,
    };

    let mut cmd = TokioCommand::new(binary);

    // Build sensible default args + user extras. Keep it safe: user controls target.
    match tool.as_str() {
        "nuclei" => {
            cmd.arg("-u").arg(&target).arg("-jsonl");
            if extra_args.is_empty() {
                cmd.args(["-t", "http/*", "-severity", "low,medium,high,critical", "-silent", "-no-color"]);
            }
        }
        "trivy" => {
            if target.contains("://") || (target.contains("/") && !target.contains(":")) {
                cmd.arg("repo").arg(&target);
            } else {
                cmd.arg("fs").arg(&target);
            }
            cmd.args(["--exit-code", "0", "--format", "json"]);
        }
        "nmap" => {
            cmd.arg("-sV").arg("-T4").arg("-Pn").arg(&target);
        }
        "osv-scanner" => {
            // Recursively scan a directory/repo for vulnerable dependencies (SCA),
            // emitting a single JSON document. Exits non-zero when vulns are found
            // — that's expected; we still read stdout.
            cmd.arg("--format").arg("json").arg("-r").arg(&target);
        }
        _ => {
            cmd.args(&extra_args);
            cmd.arg(&target);
        }
    }

    if !extra_args.is_empty() && !matches!(tool.as_str(), "nuclei" | "trivy" | "nmap" | "osv-scanner") {
        cmd.args(&extra_args);
    }

    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| format!("Failed to spawn {}: {}", tool, e))?;

    if let Some(pid) = child.id() {
        let mut map = state.pids.lock().unwrap();
        map.entry(scan_id.clone()).or_default().push(pid);
    }

    let stdout = child.stdout.take().ok_or("no stdout")?;
    let stderr = child.stderr.take().ok_or("no stderr")?;

    let mut out_reader = BufReader::new(stdout).lines();
    let mut err_reader = BufReader::new(stderr).lines();

    // Shared collectors so we can both stream and return full output
    let collected_out = Arc::new(Mutex::new(String::new()));
    let collected_err = Arc::new(Mutex::new(String::new()));

    let app_handle = app.clone();
    let scan_id_clone = scan_id.clone();
    let tool_for_parse = tool.clone();

    let out_arc = collected_out.clone();
    let err_arc = collected_err.clone();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                Ok(Some(line)) = out_reader.next_line() => {
                    {
                        let mut guard = out_arc.lock().unwrap();
                        guard.push_str(&line);
                        guard.push('\n');
                    }
                    let _ = app_handle.emit("scan-event", ScanEvent {
                        scan_id: scan_id_clone.clone(),
                        event_type: "log".into(),
                        data: serde_json::json!({ "stream": "stdout", "line": line }),
                    });

                    // "Beyond normal": parse structured findings live from JSONL tools
                    if tool_for_parse == "nuclei" {
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
                            if let Some(fdata) = map_nuclei_to_finding(&val) {
                                let _ = app_handle.emit("scan-event", ScanEvent {
                                    scan_id: scan_id_clone.clone(),
                                    event_type: "finding".into(),
                                    data: fdata,
                                });
                            }
                        }
                    }
                }
                Ok(Some(line)) = err_reader.next_line() => {
                    {
                        let mut guard = err_arc.lock().unwrap();
                        guard.push_str(&line);
                        guard.push('\n');
                    }
                    let _ = app_handle.emit("scan-event", ScanEvent {
                        scan_id: scan_id_clone.clone(),
                        event_type: "log".into(),
                        data: serde_json::json!({ "stream": "stderr", "line": line }),
                    });
                }
                else => break,
            }
        }
    });

    let status = child.wait().await.map_err(|e| e.to_string())?;
    let duration = start.elapsed().as_millis() as u64;

    // Post-process for tools that emit one big JSON at the end (Trivy)
    let stdout_full = collected_out.lock().unwrap().clone();
    if tool == "trivy" {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout_full) {
            if let Some(results) = val.get("Results").and_then(|r| r.as_array()) {
                for res in results {
                    if let Some(vulns) = res.get("Vulnerabilities").and_then(|v| v.as_array()) {
                        for v in vulns {
                            if let Some(fdata) = map_trivy_to_finding(v, &target) {
                                let _ = app.emit("scan-event", ScanEvent {
                                    scan_id: scan_id.clone(),
                                    event_type: "finding".into(),
                                    data: fdata,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // OSV-Scanner: results[].packages[].vulnerabilities[] (one JSON document).
    if tool == "osv-scanner" {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&stdout_full) {
            if let Some(results) = val.get("results").and_then(|r| r.as_array()) {
                for res in results {
                    if let Some(packages) = res.get("packages").and_then(|p| p.as_array()) {
                        for pkg in packages {
                            let p = pkg.get("package");
                            let name = p.and_then(|x| x.get("name")).and_then(|n| n.as_str()).unwrap_or("");
                            let version = p.and_then(|x| x.get("version")).and_then(|n| n.as_str()).unwrap_or("");
                            if let Some(vulns) = pkg.get("vulnerabilities").and_then(|v| v.as_array()) {
                                for v in vulns {
                                    if let Some(fdata) = map_osv_to_finding(v, name, version, &target) {
                                        let _ = app.emit("scan-event", ScanEvent {
                                            scan_id: scan_id.clone(),
                                            event_type: "finding".into(),
                                            data: fdata,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let result = ExternalScanResult {
        stdout: stdout_full,
        stderr: collected_err.lock().unwrap().clone(),
        exit_code: status.code(),
        duration_ms: duration,
    };

    let _ = app.emit("scan-event", ScanEvent {
        scan_id: scan_id.clone(),
        event_type: "complete".into(),
        data: serde_json::to_value(&result).unwrap_or_default(),
    });

    Ok(result)
}

/// Simple but effective concurrent TCP connect scanner (pure Rust, no external deps)
#[tauri::command]
async fn tcp_port_scan(
    app: tauri::AppHandle,
    scan_id: String,
    host: String,
    ports: Vec<u16>,
    concurrency: Option<usize>,
) -> Result<Vec<serde_json::Value>, String> {
    validate_target(&host)?;
    let concurrency = concurrency.unwrap_or(50);
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut tasks = Vec::new();

    let total = ports.len();
    let mut open_ports = vec![];

    for (i, port) in ports.into_iter().enumerate() {
        let sem = semaphore.clone();
        let h = host.clone();
        let app2 = app.clone();
        let sid = scan_id.clone();

        let task = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            let addr = format!("{}:{}", h, port);
            let start = std::time::Instant::now();

            let is_open = match tokio::time::timeout(
                Duration::from_millis(800),
                tokio::net::TcpStream::connect(&addr),
            )
            .await
            {
                Ok(Ok(_stream)) => true,
                _ => false,
            };

            let latency = start.elapsed().as_millis() as u64;

            if is_open {
                let finding = serde_json::json!({
                    "source": "rust-tcp",
                    "port": port,
                    "status": "open",
                    "latency_ms": latency,
                    "service": guess_service(port),
                });

                let _ = app2.emit("scan-event", ScanEvent {
                    scan_id: sid,
                    event_type: "finding".into(),
                    data: finding.clone(),
                });
                Some(finding)
            } else {
                // Optional: emit progress every N
                if i % 20 == 0 {
                    let progress = ((i as f32 / total as f32) * 100.0) as u8;
                    let _ = app2.emit("scan-event", ScanEvent {
                        scan_id: sid,
                        event_type: "progress".into(),
                        data: serde_json::json!({ "progress": progress }),
                    });
                }
                None
            }
        });
        tasks.push(task);
    }

    for t in tasks {
        if let Ok(Some(f)) = t.await {
            open_ports.push(f);
        }
    }

    // Final progress
    let _ = app.emit("scan-event", ScanEvent {
        scan_id: scan_id.clone(),
        event_type: "progress".into(),
        data: serde_json::json!({ "progress": 100 }),
    });

    Ok(open_ports)
}

/// Reject targets that could be misread as command-line flags (argument
/// injection) when appended positionally to tools like nmap, or that contain
/// whitespace/control characters. We never use a shell, so this is the relevant
/// guard rather than shell-metacharacter escaping.
fn validate_target(target: &str) -> Result<(), String> {
    let t = target.trim();
    if t.is_empty() {
        return Err("empty target".into());
    }
    if t.starts_with('-') {
        return Err(format!("target '{}' may not start with '-'", t));
    }
    if t.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("target contains whitespace or control characters".into());
    }
    Ok(())
}

fn guess_service(port: u16) -> &'static str {
    match port {
        22 => "ssh",
        80 => "http",
        443 => "https",
        445 => "smb",
        3306 => "mysql",
        5432 => "postgres",
        8080 | 8000 => "http-alt",
        8443 => "https-alt",
        _ => "unknown",
    }
}

/// Map a single Nuclei JSONL result line into a rich Finding payload for the UI.
/// This is what makes Spectra "go beyond" a raw tool — structured, correlated, prioritized data.
fn map_nuclei_to_finding(val: &serde_json::Value) -> Option<serde_json::Value> {
    let info = val.get("info")?;
    let title = info.get("name").and_then(|v| v.as_str()).unwrap_or("Nuclei detection").to_string();

    let sev_raw = info
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("info")
        .to_lowercase();
    let severity = match sev_raw.as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        _ => "info",
    };

    let asset = val
        .get("matched-at")
        .and_then(|v| v.as_str())
        .or_else(|| val.get("host").and_then(|v| v.as_str()))
        .unwrap_or("unknown")
        .to_string();

    let description = info
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let evidence = val
        .get("curl-command")
        .and_then(|v| v.as_str())
        .or_else(|| val.get("extracted-results").and_then(|v| v.as_str()))
        .unwrap_or(&val.to_string())
        .to_string();

    let recommendation = format!(
        "Review the '{}' Nuclei template. Update/patch the affected component and restrict exposure.",
        title
    );

    let tags = info.get("tags").cloned().unwrap_or(serde_json::json!([]));

    let exploit = match severity {
        "critical" => 90,
        "high" => 75,
        "medium" => 55,
        _ => 35,
    };

    // Include extra context for the AI co-pilot and graph
    Some(serde_json::json!({
        "source": "nuclei",
        "title": title,
        "severity": severity,
        "asset": asset,
        "evidence": evidence,
        "description": description,
        "recommendation": recommendation,
        "tags": tags,
        "exploitability": exploit,
        "cwe": info.get("classification").and_then(|c| c.get("cwe-id")).cloned().unwrap_or(serde_json::json!([])),
        "cve": info.get("classification").and_then(|c| c.get("cve-id")).cloned().unwrap_or(serde_json::json!([])),
        "template": info.get("template-id").and_then(|t| t.as_str()).unwrap_or(""),
    }))
}

/// Map Trivy vulnerability entries (from the big JSON result) into Finding payloads.
fn map_trivy_to_finding(v: &serde_json::Value, target: &str) -> Option<serde_json::Value> {
    let id = v.get("VulnerabilityID").and_then(|x| x.as_str()).unwrap_or("Trivy vuln");
    let pkg = v.get("PkgName").and_then(|x| x.as_str()).unwrap_or("");
    let title = if pkg.is_empty() { id.to_string() } else { format!("{} in {}", id, pkg) };

    let sev_raw = v.get("Severity").and_then(|x| x.as_str()).unwrap_or("UNKNOWN").to_lowercase();
    let severity = match sev_raw.as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        _ => "info",
    };

    let description = v.get("Description").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let evidence = format!("Installed version: {} — Fixed in: {}",
        v.get("InstalledVersion").and_then(|x| x.as_str()).unwrap_or("?"),
        v.get("FixedVersion").and_then(|x| x.as_str()).unwrap_or("n/a"));

    let exploit = match severity {
        "critical" => 85,
        "high" => 70,
        _ => 45,
    };

    Some(serde_json::json!({
        "source": "trivy",
        "title": title,
        "severity": severity,
        "asset": target,
        "evidence": evidence,
        "description": description,
        "recommendation": "Update the vulnerable package to a fixed version. Use SBOM and dependency scanning in CI.",
        "tags": ["trivy", "dependency", "cve"],
        "exploitability": exploit,
        "cwe": v.get("CweIDs").cloned().unwrap_or(serde_json::json!([])),
        "cve": v.get("VulnerabilityID").and_then(|x| x.as_str()).map(|s| vec![s]).unwrap_or(vec![]),
    }))
}

/// Map an OSV-Scanner vulnerability (Software Composition Analysis) into a Finding.
fn map_osv_to_finding(vuln: &serde_json::Value, pkg_name: &str, version: &str, target: &str) -> Option<serde_json::Value> {
    let id = vuln.get("id").and_then(|x| x.as_str()).unwrap_or("OSV advisory");
    let title = if pkg_name.is_empty() { id.to_string() } else { format!("{} in {}", id, pkg_name) };

    // GHSA advisories expose database_specific.severity; default to medium since
    // OSV only reports genuine vulnerabilities.
    let sev_raw = vuln
        .get("database_specific")
        .and_then(|d| d.get("severity"))
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_lowercase();
    let severity = match sev_raw.as_str() {
        "critical" => "critical",
        "high" => "high",
        "moderate" | "medium" => "medium",
        "low" => "low",
        _ => "medium",
    };

    let summary = vuln.get("summary").and_then(|x| x.as_str()).unwrap_or("");
    let details = vuln.get("details").and_then(|x| x.as_str()).unwrap_or("");
    let description = if summary.is_empty() {
        details.chars().take(400).collect::<String>()
    } else {
        summary.to_string()
    };

    let cves: Vec<String> = vuln
        .get("aliases")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter(|s| s.starts_with("CVE-"))
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    let exploit = match severity {
        "critical" => 85,
        "high" => 70,
        "medium" => 50,
        _ => 40,
    };

    Some(serde_json::json!({
        "source": "osv-scanner",
        "title": title,
        "severity": severity,
        "asset": target,
        "evidence": format!("Package {} {} — advisory {}", pkg_name, version, id),
        "description": description,
        "recommendation": "Upgrade the affected dependency to a fixed version. Review the OSV/GHSA advisory for patched releases.",
        "tags": ["osv", "dependency", "sca"],
        "exploitability": exploit,
        "cve": cves,
    }))
}

/// Lightweight HTTP tech + header probe (uses reqwest)
#[tauri::command]
async fn http_probe(target: String) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(6))
        .user_agent("Spectra/0.1 (+https://spectra.local)")
        .danger_accept_invalid_certs(true) // for vuln scanning authorized targets
        .build()
        .map_err(|e| e.to_string())?;

    validate_target(&target)?;
    let url = if target.starts_with("http") { target } else { format!("http://{}", target) };

    let resp = client.get(&url).send().await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let headers: Vec<_> = resp.headers().iter().map(|(k, v)| {
        (k.to_string(), v.to_str().unwrap_or("").to_string())
    }).collect();

    let server = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("server")).map(|(_, v)| v.clone());
    let powered = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("x-powered-by")).map(|(_, v)| v.clone());

    Ok(serde_json::json!({
        "url": url,
        "status": status,
        "server": server,
        "x_powered_by": powered,
        "headers_sample": headers.into_iter().take(12).collect::<Vec<_>>(),
    }))
}

/// Normalise a user-supplied Ollama endpoint: trim, require http(s), strip a
/// trailing slash. Returns the base URL (without a path).
fn normalize_ollama_endpoint(endpoint: &str) -> Result<String, String> {
    let e = endpoint.trim().trim_end_matches('/');
    if !(e.starts_with("http://") || e.starts_with("https://")) {
        return Err("Ollama endpoint must start with http:// or https://".into());
    }
    Ok(e.to_string())
}

/// Proxy a generation request to the local Ollama instance from Rust.
/// This avoids the webview making a cross-origin fetch (no CORS, and the
/// Ollama host no longer needs to be allow-listed in the CSP connect-src).
#[tauri::command]
async fn ollama_generate(prompt: String, model: String, endpoint: String) -> Result<String, String> {
    let base = normalize_ollama_endpoint(&endpoint)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| e.to_string())?;

    let body = serde_json::json!({
        "model": model,
        "prompt": prompt,
        "stream": false,
        "options": { "temperature": 0.3, "num_predict": 380 }
    });

    let resp = client
        .post(format!("{}/api/generate", base))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Ollama not reachable: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Ollama returned HTTP {}", resp.status().as_u16()));
    }

    let val: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    let reply = val
        .get("response")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();

    if reply.is_empty() {
        return Err("Ollama returned an empty response".into());
    }
    Ok(reply)
}

/// Stream a generation from Ollama, emitting each token to the frontend via a
/// Tauri Channel as it arrives. Returns once the stream is complete.
#[tauri::command]
async fn ollama_generate_stream(
    prompt: String,
    model: String,
    endpoint: String,
    on_token: Channel<String>,
) -> Result<(), String> {
    let base = normalize_ollama_endpoint(&endpoint)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| e.to_string())?;

    let body = serde_json::json!({
        "model": model,
        "prompt": prompt,
        "stream": true,
        "options": { "temperature": 0.3 }
    });

    let mut resp = client
        .post(format!("{}/api/generate", base))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Ollama not reachable: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Ollama returned HTTP {}", resp.status().as_u16()));
    }

    // Ollama streams newline-delimited JSON. Buffer bytes and decode only
    // complete lines, so a multi-byte char split across chunks is never mangled.
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        buf.extend_from_slice(&chunk);
        while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = buf.drain(..=pos).collect();
            let line = String::from_utf8_lossy(&line);
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
                if let Some(tok) = val.get("response").and_then(|v| v.as_str()) {
                    if !tok.is_empty() {
                        let _ = on_token.send(tok.to_string());
                    }
                }
            }
        }
    }
    Ok(())
}

/// List models installed in the local Ollama instance (GET /api/tags).
#[tauri::command]
async fn ollama_models(endpoint: String) -> Result<Vec<String>, String> {
    let base = normalize_ollama_endpoint(&endpoint)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .get(format!("{}/api/tags", base))
        .send()
        .await
        .map_err(|e| format!("Ollama not reachable: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Ollama returned HTTP {}", resp.status().as_u16()));
    }

    let val: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    let names = val
        .get("models")
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(names)
}

/// CVE store stats (how many CVE rows + KEV entries are loaded).
#[tauri::command]
async fn cve_stats(db: tauri::State<'_, Db>) -> Result<serde_json::Value, String> {
    let conn = db.0.lock().map_err(|e| e.to_string())?;
    let cve = vuln_db::cve_count(&conn).map_err(|e| e.to_string())?;
    let kev = vuln_db::kev_count(&conn).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({ "cve_rows": cve, "kev_entries": kev }))
}

/// Match a detected product + version against the CVE store.
#[tauri::command]
async fn match_service_cves(
    product: String,
    version: String,
    db: tauri::State<'_, Db>,
) -> Result<Vec<vuln_db::CveMatch>, String> {
    let conn = db.0.lock().map_err(|e| e.to_string())?;
    vuln_db::match_cves(&conn, &product, &version).map_err(|e| e.to_string())
}

/// Import an NVD CVE feed (JSON, API 2.0 shape). Returns rows inserted.
#[tauri::command]
async fn import_cve_feed(json: String, db: tauri::State<'_, Db>) -> Result<usize, String> {
    let mut conn = db.0.lock().map_err(|e| e.to_string())?;
    vuln_db::import_nvd_json(&mut conn, &json)
}

/// Import the CISA KEV (Known Exploited Vulnerabilities) catalog JSON. Returns entries inserted.
#[tauri::command]
async fn import_kev_feed(json: String, db: tauri::State<'_, Db>) -> Result<usize, String> {
    let mut conn = db.0.lock().map_err(|e| e.to_string())?;
    vuln_db::import_kev_json(&mut conn, &json)
}

/// List the YAML check plugins currently installed in the app's plugins dir.
#[tauri::command]
async fn list_plugins(app: tauri::AppHandle) -> Result<Vec<serde_json::Value>, String> {
    let dir = app.path().app_local_data_dir().map_err(|e| e.to_string())?.join("plugins");
    let checks = plugins::load_plugins(&dir);
    Ok(checks
        .iter()
        .map(|c| serde_json::json!({ "id": c.id, "name": c.name, "severity": c.severity, "path": c.request.path }))
        .collect())
}

/// Run every installed plugin check against a target, emitting a finding per
/// match. Returns the number of matches.
#[tauri::command]
async fn run_plugin_checks(app: tauri::AppHandle, scan_id: String, target: String) -> Result<usize, String> {
    validate_target(&target)?;
    let dir = app.path().app_local_data_dir().map_err(|e| e.to_string())?.join("plugins");
    let checks = plugins::load_plugins(&dir);
    if checks.is_empty() {
        return Ok(0);
    }

    let base = if target.starts_with("http") { target.clone() } else { format!("http://{}", target) };
    let base = base.trim_end_matches('/').to_string();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .user_agent("Spectra/0.1")
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| e.to_string())?;

    let mut matched = 0usize;
    for check in &checks {
        let path = if check.request.path.starts_with('/') {
            check.request.path.clone()
        } else {
            format!("/{}", check.request.path)
        };
        let url = format!("{}{}", base, path);
        let method = check.request.method.clone().unwrap_or_else(|| "GET".into()).to_uppercase();
        let req = match method.as_str() {
            "POST" => client.post(&url),
            "HEAD" => client.head(&url),
            _ => client.get(&url),
        };
        if let Ok(resp) = req.send().await {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            if plugins::check_matches(check, status, &body) {
                matched += 1;
                let _ = app.emit("scan-event", ScanEvent {
                    scan_id: scan_id.clone(),
                    event_type: "finding".into(),
                    data: plugins::check_to_finding(check, &url),
                });
            }
        }
    }
    Ok(matched)
}

#[tauri::command]
async fn cancel_real_scan(
    app: tauri::AppHandle,
    scan_id: String,
    state: tauri::State<'_, RunningScans>,
) -> Result<(), String> {
    let pids = {
        let mut map = state.pids.lock().unwrap();
        map.remove(&scan_id).unwrap_or_default()
    };

    for pid in pids {
        // Cross-platform process termination. On Windows, /T also kills the
        // child process tree (tools like nmap/nuclei spawn helpers).
        #[cfg(windows)]
        {
            let _ = std::process::Command::new("taskkill")
                .args(["/PID", &pid.to_string(), "/F", "/T"])
                .output();
        }
        #[cfg(unix)]
        {
            let _ = std::process::Command::new("kill")
                .args(["-9", &pid.to_string()])
                .output();
        }
    }

    let _ = app.emit("scan-event", ScanEvent {
        scan_id: scan_id.clone(),
        event_type: "cancelled".into(),
        data: serde_json::json!({}),
    });

    Ok(())
}

// ── SQLite-backed scan persistence ──────────────────────────────────────────
// A `scans` table holds scan metadata; a `findings` table holds one row per
// finding (with the full finding JSON in `data`, plus denormalized columns for
// querying). The frontend contract is unchanged: save_scan takes a whole Scan
// value, load_scans returns an array of whole Scan values.

fn init_schema(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS scans (
            id           TEXT PRIMARY KEY,
            name         TEXT,
            targets      TEXT,
            profile      TEXT,
            status       TEXT,
            started_at   TEXT,
            completed_at TEXT,
            progress     INTEGER
        );
        CREATE TABLE IF NOT EXISTS findings (
            id       TEXT PRIMARY KEY,
            scan_id  TEXT NOT NULL,
            severity TEXT,
            status   TEXT,
            title    TEXT,
            asset    TEXT,
            data     TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);",
    )?;
    Ok(())
}

/// Upsert a scan and replace its findings, atomically.
fn db_save_scan(conn: &mut rusqlite::Connection, scan: &serde_json::Value) -> rusqlite::Result<()> {
    let id = scan.get("id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
    let targets = scan.get("targets").map(|v| v.to_string()).unwrap_or_else(|| "[]".to_string());
    let str_of = |k: &str| scan.get(k).and_then(|v| v.as_str()).map(|s| s.to_string());
    let progress = scan.get("progress").and_then(|v| v.as_i64()).unwrap_or(0);

    let tx = conn.transaction()?;
    tx.execute(
        "INSERT OR REPLACE INTO scans (id,name,targets,profile,status,started_at,completed_at,progress)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        rusqlite::params![id, str_of("name"), targets, str_of("profile"), str_of("status"), str_of("startedAt"), str_of("completedAt"), progress],
    )?;
    tx.execute("DELETE FROM findings WHERE scan_id = ?1", rusqlite::params![id])?;
    if let Some(findings) = scan.get("findings").and_then(|v| v.as_array()) {
        for f in findings {
            let fid = f.get("id").and_then(|v| v.as_str()).unwrap_or("");
            if fid.is_empty() {
                continue;
            }
            let fstr = |k: &str| f.get(k).and_then(|v| v.as_str()).map(|s| s.to_string());
            tx.execute(
                "INSERT OR REPLACE INTO findings (id,scan_id,severity,status,title,asset,data)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                rusqlite::params![fid, id, fstr("severity"), fstr("status"), fstr("title"), fstr("asset"), f.to_string()],
            )?;
        }
    }
    tx.commit()
}

/// Load all scans (newest first), each reassembled with its findings array.
fn db_load_scans(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<serde_json::Value>> {
    let mut stmt = conn.prepare(
        "SELECT id,name,targets,profile,status,started_at,completed_at,progress FROM scans ORDER BY started_at DESC",
    )?;
    let metas: Vec<(String, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, i64)> = stmt
        .query_map([], |row| {
            Ok((
                row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?,
                row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let mut out = Vec::with_capacity(metas.len());
    for (id, name, targets, profile, status, started_at, completed_at, progress) in metas {
        let mut fstmt = conn.prepare("SELECT data FROM findings WHERE scan_id = ?1")?;
        let findings: Vec<serde_json::Value> = fstmt
            .query_map([&id], |row| row.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .filter_map(|s| serde_json::from_str(&s).ok())
            .collect();

        let targets_val: serde_json::Value =
            targets.as_deref().and_then(|t| serde_json::from_str(t).ok()).unwrap_or_else(|| serde_json::json!([]));

        out.push(serde_json::json!({
            "id": id,
            "name": name,
            "targets": targets_val,
            "profile": profile,
            "status": status,
            "startedAt": started_at,
            "completedAt": completed_at,
            "progress": progress,
            "findings": findings,
        }));
    }
    Ok(out)
}

/// One-time migration: if the DB is empty, import any legacy `scan_*.json` files.
fn import_legacy_json(conn: &mut rusqlite::Connection, dir: &std::path::Path) {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM scans", [], |r| r.get(0)).unwrap_or(0);
    if count > 0 {
        return;
    }
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.filter_map(|e| e.ok()) {
            if let Some(n) = entry.file_name().to_str() {
                if n.starts_with("scan_") && n.ends_with(".json") {
                    if let Ok(content) = std::fs::read_to_string(entry.path()) {
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                            let _ = db_save_scan(conn, &val);
                        }
                    }
                }
            }
        }
    }
}

#[tauri::command]
async fn save_scan(scan: serde_json::Value, db: tauri::State<'_, Db>) -> Result<(), String> {
    let mut conn = db.0.lock().map_err(|e| e.to_string())?;
    db_save_scan(&mut conn, &scan).map_err(|e| e.to_string())
}

#[tauri::command]
async fn load_scans(db: tauri::State<'_, Db>) -> Result<Vec<serde_json::Value>, String> {
    let conn = db.0.lock().map_err(|e| e.to_string())?;
    db_load_scans(&conn).map_err(|e| e.to_string())
}

#[tauri::command]
async fn delete_scan(id: String, db: tauri::State<'_, Db>) -> Result<(), String> {
    let conn = db.0.lock().map_err(|e| e.to_string())?;
    conn.execute("DELETE FROM findings WHERE scan_id = ?1", rusqlite::params![id]).map_err(|e| e.to_string())?;
    conn.execute("DELETE FROM scans WHERE id = ?1", rusqlite::params![id]).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(RunningScans::default())
        .setup(|app| {
            if cfg!(debug_assertions) {
                let _ = app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                );
            }

            // Open (or create) the SQLite store in the app data dir.
            let dir = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
            std::fs::create_dir_all(&dir).ok();
            let mut conn = rusqlite::Connection::open(dir.join("spectra.db")).map_err(|e| e.to_string())?;
            init_schema(&conn).map_err(|e| e.to_string())?;
            import_legacy_json(&mut conn, &dir); // best-effort migration from the old JSON files
            // CVE matching store (seeded with well-known CVEs until a full NVD feed is imported).
            vuln_db::init_cve_schema(&conn).map_err(|e| e.to_string())?;
            vuln_db::seed_known_cves(&mut conn).map_err(|e| e.to_string())?;
            app.manage(Db(Mutex::new(conn)));

            // Seed example YAML check plugins on first run.
            let plugins_dir = dir.join("plugins");
            std::fs::create_dir_all(&plugins_dir).ok();
            plugins::seed_example_plugins(&plugins_dir);

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            detect_installed_tools,
            run_external_scan,
            tcp_port_scan,
            http_probe,
            ollama_generate,
            ollama_generate_stream,
            ollama_models,
            save_scan,
            load_scans,
            delete_scan,
            list_plugins,
            run_plugin_checks,
            cve_stats,
            match_service_cves,
            import_cve_feed,
            import_kev_feed,
            cancel_real_scan,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osv_mapping_builds_finding_with_cve_alias() {
        let vuln = serde_json::json!({
            "id": "GHSA-aaaa-bbbb-cccc",
            "summary": "Prototype pollution in lodash",
            "aliases": ["CVE-2021-23337", "GHSA-aaaa-bbbb-cccc"],
            "database_specific": { "severity": "HIGH" }
        });
        let f = map_osv_to_finding(&vuln, "lodash", "4.17.0", "/repo").expect("should map");
        assert_eq!(f["title"], "GHSA-aaaa-bbbb-cccc in lodash");
        assert_eq!(f["severity"], "high");
        assert_eq!(f["source"], "osv-scanner");
        assert_eq!(f["asset"], "/repo");
        assert_eq!(f["cve"][0], "CVE-2021-23337"); // CVE extracted from aliases
        assert_eq!(f["exploitability"], 70);
    }

    #[test]
    fn osv_mapping_defaults_unknown_severity_to_medium() {
        let vuln = serde_json::json!({ "id": "OSV-1", "summary": "x" });
        let f = map_osv_to_finding(&vuln, "pkg", "1.0", "/repo").unwrap();
        assert_eq!(f["severity"], "medium"); // OSV only reports real vulns
        assert_eq!(f["cve"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn sqlite_roundtrip_preserves_scan_and_findings() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        let scan = serde_json::json!({
            "id": "scan_1", "name": "Test", "targets": ["https://example.com"], "profile": "Web",
            "status": "completed", "startedAt": "2026-01-01T00:00:00Z", "completedAt": "2026-01-01T00:01:00Z", "progress": 100,
            "findings": [
                {"id": "f1", "severity": "high", "status": "confirmed", "title": "SQLi", "asset": "https://example.com", "tags": ["web"]},
                {"id": "f2", "severity": "low", "title": "Header", "asset": "example.com", "tags": []}
            ]
        });
        db_save_scan(&mut conn, &scan).unwrap();
        let loaded = db_load_scans(&conn).unwrap();
        assert_eq!(loaded.len(), 1);
        let s = &loaded[0];
        assert_eq!(s["id"], "scan_1");
        assert_eq!(s["name"], "Test");
        assert_eq!(s["targets"][0], "https://example.com");
        assert_eq!(s["progress"], 100);
        let findings = s["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 2);
        let f1 = findings.iter().find(|f| f["id"] == "f1").unwrap();
        assert_eq!(f1["status"], "confirmed"); // triage status survives the round-trip
        assert_eq!(f1["severity"], "high");
    }

    #[test]
    fn sqlite_save_is_idempotent_and_replaces_findings() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        let mut scan = serde_json::json!({
            "id": "s", "name": "n", "targets": [], "profile": "p", "status": "running", "startedAt": "t", "progress": 0,
            "findings": [{"id": "a", "severity": "low", "title": "x", "asset": "h"}]
        });
        db_save_scan(&mut conn, &scan).unwrap();
        scan["findings"] = serde_json::json!([
            {"id": "b", "severity": "high", "title": "y", "asset": "h"},
            {"id": "c", "severity": "medium", "title": "z", "asset": "h"}
        ]);
        db_save_scan(&mut conn, &scan).unwrap();
        let loaded = db_load_scans(&conn).unwrap();
        assert_eq!(loaded.len(), 1); // re-save updates, not duplicates
        assert_eq!(loaded[0]["findings"].as_array().unwrap().len(), 2); // old finding 'a' replaced
    }

    #[test]
    fn validate_target_accepts_normal_targets() {
        assert!(validate_target("example.com").is_ok());
        assert!(validate_target("https://example.com/path").is_ok());
        assert!(validate_target("10.10.14.7").is_ok());
        assert!(validate_target("10.0.0.0/24").is_ok());
    }

    #[test]
    fn validate_target_rejects_flag_injection() {
        // The argv-injection vector: a "target" that nmap would read as a flag.
        assert!(validate_target("-oN/etc/passwd").is_err());
        assert!(validate_target("--script=evil").is_err());
        assert!(validate_target("").is_err());
        assert!(validate_target("a b").is_err()); // whitespace
        assert!(validate_target("a\nb").is_err()); // control char
    }

    #[test]
    fn normalize_ollama_endpoint_trims_and_validates() {
        assert_eq!(normalize_ollama_endpoint("http://127.0.0.1:11434/").unwrap(), "http://127.0.0.1:11434");
        assert_eq!(normalize_ollama_endpoint("  https://host:1234  ").unwrap(), "https://host:1234");
        assert!(normalize_ollama_endpoint("127.0.0.1:11434").is_err()); // missing scheme
        assert!(normalize_ollama_endpoint("ftp://x").is_err());
    }

    #[test]
    fn guess_service_maps_known_ports() {
        assert_eq!(guess_service(22), "ssh");
        assert_eq!(guess_service(443), "https");
        assert_eq!(guess_service(9999), "unknown");
    }

    #[test]
    fn nuclei_mapping_extracts_core_fields() {
        let line = serde_json::json!({
            "matched-at": "https://t.example/login",
            "info": {
                "name": "Exposed admin panel",
                "severity": "High",
                "description": "Admin panel reachable",
                "tags": ["panel", "exposure"],
                "classification": { "cve-id": ["CVE-2023-1234"], "cwe-id": ["CWE-284"] },
                "template-id": "exposed-panel"
            }
        });
        let f = map_nuclei_to_finding(&line).expect("should map");
        assert_eq!(f["title"], "Exposed admin panel");
        assert_eq!(f["severity"], "high"); // normalised to lowercase
        assert_eq!(f["asset"], "https://t.example/login");
        assert_eq!(f["source"], "nuclei");
        assert_eq!(f["exploitability"], 75);
        assert_eq!(f["template"], "exposed-panel");
    }

    #[test]
    fn nuclei_mapping_defaults_unknown_severity_to_info() {
        let line = serde_json::json!({ "info": { "name": "x", "severity": "bogus" } });
        let f = map_nuclei_to_finding(&line).unwrap();
        assert_eq!(f["severity"], "info");
        assert_eq!(f["exploitability"], 35);
    }

    #[test]
    fn nuclei_mapping_requires_info() {
        assert!(map_nuclei_to_finding(&serde_json::json!({ "host": "x" })).is_none());
    }

    #[test]
    fn trivy_mapping_builds_titled_finding() {
        let v = serde_json::json!({
            "VulnerabilityID": "CVE-2021-1111",
            "PkgName": "openssl",
            "Severity": "CRITICAL",
            "InstalledVersion": "1.0.0",
            "FixedVersion": "1.0.1",
            "Description": "bad",
            "CweIDs": ["CWE-119"]
        });
        let f = map_trivy_to_finding(&v, "repo").expect("should map");
        assert_eq!(f["title"], "CVE-2021-1111 in openssl");
        assert_eq!(f["severity"], "critical");
        assert_eq!(f["source"], "trivy");
        assert_eq!(f["asset"], "repo");
        assert_eq!(f["exploitability"], 85);
        assert_eq!(f["cve"][0], "CVE-2021-1111");
    }
}
