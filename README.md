# Spectra

**A modern vulnerability scanner with a beautiful GUI and capabilities that go far beyond traditional tools.**

> See what others miss. Correlate. Analyze with local AI. Visualize attack paths. Extensible by design.

## What makes Spectra different ("beyond normal scanners")

- **Stunning modern desktop-class GUI** (React + Tailwind + professional dark security aesthetic) — works instantly in browser during development, becomes a native desktop app via Tauri.
- **Live streaming findings** with rich metadata (CVSS, exploitability scores, CWE/OWASP, evidence, recommendations).
- **Intelligent correlation engine** — not just a list of vulns. Detects realistic multi-step attack paths and surfaces them with high exploitability scores.
- **Local AI Co-pilot** (Ollama-powered) — chat with your findings using fully private models running on your machine. Ask for attack path suggestions, validation steps, risk narratives, or next recon moves.
- **Interactive Attack Graph** — watch hosts, services, and high-value findings light up in real time as the scan progresses.
- **Powerful filtering, virtual tables, instant exports** (JSON/CSV/Markdown ready for ticketing and SARIF consumers).
- **Safety-first** — prominent banners, confirmation for active techniques, local-only data, clear auditability.
- **Future-proof architecture**: The UI contracts are designed to be driven 1:1 by a Rust core + external tool orchestration (nuclei, nmap, trivy, osv-scanner, custom plugins).

## Current Status (v0.1)

✅ Fully-functional GUI (New Scan wizard, virtualized findings table, detail drawer, filters, interactive attack graph, AI co-pilot chat, reports, dashboard)  
✅ `⌘K` / `Ctrl+K` command palette (cmdk)  
✅ Browser scan **simulator** for demos — every simulated finding is tagged `source: simulator` and the UI shows a prominent "SIMULATED DATA" banner so demo data is never mistaken for real results  
✅ **Real native engine (Tauri + Rust)** — implemented:
  - Concurrent pure-Rust TCP connect scanner (semaphore-bounded)
  - External tool orchestration: **Nuclei** (live JSONL → rich findings), **Trivy** (JSON → findings), **Nmap**, with PATH + WinGet auto-detection and per-scan cancellation
  - **Multi-target** scans (every target gets the full toolchain; completion waits for all jobs to settle)
  - Native HTTP banner/header probe (reqwest)
  - Cross-platform process cancellation (taskkill /T on Windows, kill -9 on Unix)
✅ **Analyst triage** — mark findings Open / Confirmed / False-positive / Triaged, filter by status, and carry it into every export  
✅ **Local AI co-pilot (Ollama)** — proxied through Rust (no CORS, nothing external in the CSP), **streaming** token-by-token, with a **configurable model + endpoint** and one-click model detection  
✅ **Exports** — JSON, CSV (formula-injection-safe), Markdown, and **SARIF 2.1** for DefectDojo / GitHub code scanning  
✅ File-based scan persistence in the app data dir (survives restarts)  
✅ Security hardening: strict Content-Security-Policy, least-privilege Tauri capabilities (no shell-plugin surface — process execution is native Rust only), scan-target validation against argument-injection  
✅ Tests: Rust unit tests for the Nuclei/Trivy mappers, target validator, and Ollama-endpoint normalizer; Vitest for export (CSV + SARIF), severity, and payload validation  
🚧 SQLite-backed durable storage (currently localStorage in browser + JSON files in desktop)  
🚧 PDF / HTML executive summary, richer correlation, plugin system

## Quick Start (right now)

```powershell
cd $env:USERPROFILE\Projects\spectra
pnpm install          # already done if you followed the build session
pnpm dev
```

Open http://localhost:5173

Press `/` or `Cmd/Ctrl + K` to open the New Scan wizard immediately.

Ollama users: make sure `ollama serve` is running and you have pulled a model (`ollama pull llama3.2` or similar). Spectra will use it automatically for the Co-pilot.

## Turning it into a real native desktop app (Tauri + Rust)

1. Ensure Rust is installed (https://rustup.rs) and works in your normal terminal:
   ```powershell
   rustc --version
   cargo --version
   ```

2. Add Tauri CLI and scaffold the native side (or we continue the build together):
   ```powershell
   cd $env:USERPROFILE\Projects\spectra
   pnpm add -D @tauri-apps/cli
   pnpm tauri init
   ```

3. In `src-tauri/tauri.conf.json` point the dev URL to the Vite server and build output to `dist`.

4. Implement real scanning power in Rust (`src-tauri/src/main.rs` + commands):
   - High-performance concurrent TCP scanning
   - HTTP probes + banner grabbing with reqwest
   - Process orchestration for nuclei / nmap / trivy (with PATH detection)
   - SQLite via rusqlite/sqlx for durable storage
   - Event emission to the frontend for live updates
   - Plugin loader for custom checks

The frontend types in `App.tsx` (`Finding`, `Scan`, etc.) are intentionally the contract the Rust side will fulfill via `invoke()`.

## Safety & Ethics

Spectra is a tool for **authorized** security assessments, red teaming, purple teaming, and defensive engineering only.

- Never scan targets without explicit written permission.
- Default to passive / read-only techniques where possible.
- All actions against targets are performed locally and logged.

## Roadmap Highlights

- Real multi-threaded Rust scanner core
- First-class Nuclei + Nmap + Trivy + OSV orchestration with result enrichment
- Advanced plugin system (YAML + WASM + native)
- SBOM import + dependency risk + cloud misconfig modules
- Scheduled / continuous scanning mode + agent
- Professional PDF + SARIF + Jira/Linear export
- Tauri production builds for Windows, macOS, Linux (tiny, secure, native menus + system tray)
- False-positive reduction heuristics + ML-lite scoring using local models

## Contributing / Next Session Ideas

This project was bootstrapped live. The next logical big pieces:
1. Wire real port scanning + HTTP fingerprinting in Rust
2. Call external tools safely and merge their output into the same Finding model
3. Turn the simple SVG graph into a full @xyflow interactive component with path highlighting
4. Add a proper command palette (cmdk is already installed)
5. Package as signed Windows .exe + installer

Let's keep building.

---

Built with ❤️ for people who are tired of mediocre scanner UIs and checkbox outputs.
