use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Stdio;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tauri::{Emitter, Manager};
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

#[tauri::command]
async fn detect_installed_tools(app: tauri::AppHandle) -> Result<Vec<ToolStatus>, String> {
    let tools = vec!["nmap", "nuclei", "trivy"];
    let mut results = Vec::new();

    for tool in tools {
        // Use shell plugin sidecar detection + direct which
        let (available, path, version) = match tool {
            "nuclei" => check_tool("nuclei", vec!["-version"]).await,
            "trivy" => check_tool("trivy", vec!["version"]).await,
            "nmap" => check_tool("nmap", vec!["-V"]).await,
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

    // Resolve the binary (prefer direct name so PATH including user additions works)
    let binary = match tool.as_str() {
        "nuclei" => "nuclei",
        "trivy" => "trivy",
        "nmap" => "nmap",
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
        _ => {
            cmd.args(&extra_args);
            cmd.arg(&target);
        }
    }

    if !extra_args.is_empty() && !matches!(tool.as_str(), "nuclei" | "trivy" | "nmap") {
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

/// Lightweight HTTP tech + header probe (uses reqwest)
#[tauri::command]
async fn http_probe(target: String) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(6))
        .user_agent("Spectra/0.1 (+https://spectra.local)")
        .danger_accept_invalid_certs(true) // for vuln scanning authorized targets
        .build()
        .map_err(|e| e.to_string())?;

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
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .output();
    }

    let _ = app.emit("scan-event", ScanEvent {
        scan_id: scan_id.clone(),
        event_type: "cancelled".into(),
        data: serde_json::json!({}),
    });

    Ok(())
}

/// Simple file-based persistence for scans (goes beyond in-memory only).
/// Saves to the app's local data directory so history survives restarts.
#[tauri::command]
async fn save_scan(app: tauri::AppHandle, scan: serde_json::Value) -> Result<(), String> {
    let dir = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).ok();
    let id = scan
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let path = dir.join(format!("scan_{}.json", id));
    let pretty = serde_json::to_string_pretty(&scan).map_err(|e| e.to_string())?;
    std::fs::write(path, pretty).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn load_scans(app: tauri::AppHandle) -> Result<Vec<serde_json::Value>, String> {
    let dir = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for entry in rd.filter_map(|e| e.ok()) {
            let name = entry.file_name();
            if let Some(n) = name.to_str() {
                if n.starts_with("scan_") && n.ends_with(".json") {
                    if let Ok(content) = std::fs::read_to_string(entry.path()) {
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                            out.push(val);
                        }
                    }
                }
            }
        }
    }
    Ok(out)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(RunningScans::default())
        .setup(|app| {
            if cfg!(debug_assertions) {
                let _ = app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                );
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            detect_installed_tools,
            run_external_scan,
            tcp_port_scan,
            http_probe,
            save_scan,
            load_scans,
            cancel_real_scan,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
