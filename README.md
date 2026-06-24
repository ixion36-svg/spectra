# Spectra

**A modern vulnerability scanner with a beautiful GUI and capabilities that go far beyond traditional tools.**

> See what others miss. Correlate. Analyze with local AI. Visualize attack paths. Extensible by design.

## What makes Spectra different ("beyond normal scanners")

- **Stunning modern desktop-class GUI** (React + Tailwind + professional dark security aesthetic) — works instantly in browser during development, becomes a native desktop app via Tauri.
- **Live streaming findings** with rich metadata (CVSS, exploitability scores, CWE/OWASP, evidence, recommendations).
- **Intelligent correlation engine** — not just a list of vulns. Detects realistic multi-step attack paths and surfaces them with high exploitability scores.
- **Local AI Co-pilot** (Ollama-powered) — chat with your findings using fully private models running on your machine. Ask for attack path suggestions, validation steps, risk narratives, or next recon moves.
- **Interactive Attack Graph** — watch hosts, services, and high-value findings light up in real time as the scan progresses.
- **Powerful filtering, virtualized tables, analyst triage, instant exports** — JSON, CSV, Markdown, and **SARIF 2.1** for DefectDojo / GitHub code scanning.
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
✅ **SQLite persistence** in the desktop app (`scans` + `findings` tables in the app data dir, with a one-time import of any legacy JSON scans); localStorage is the browser-only fallback  
✅ Security hardening: strict Content-Security-Policy, least-privilege Tauri capabilities (no shell-plugin surface — process execution is native Rust only), scan-target validation against argument-injection  
✅ Tests: Rust unit tests for the Nuclei/Trivy mappers, target validator, Ollama-endpoint normalizer, and SQLite round-trip; Vitest for export (CSV + SARIF), severity, host parsing, and payload validation  
🚧 PDF / HTML executive summary, richer correlation, plugin system

## Quick Start (browser dev)

```bash
git clone https://github.com/ixion36-svg/spectra.git
cd spectra
pnpm install
pnpm dev
```

Open http://localhost:5173. In the browser, scans run against the built-in
**simulator** (clearly labelled demo data) — for real scanning, run the desktop
app (below).

- Press `/` to jump to the New Scan view, or `⌘K` / `Ctrl+K` for the command palette.
- **Ollama co-pilot:** run `ollama serve` and pull a model (`ollama pull llama3.2`).
  The model and endpoint are configurable in **Settings** (or click "Detect
  installed models").

### Scripts

| Command | What |
|---|---|
| `pnpm dev` | Vite dev server (browser) |
| `pnpm build` | Type-check + production build |
| `pnpm test` | Vitest unit tests |
| `pnpm lint` | ESLint |
| `pnpm tauri:dev` | Run the native desktop app (real engine) |
| `pnpm tauri:build` | Build a packaged desktop binary |

## Running the desktop app (Tauri + Rust)

The native engine is **already built** (`src-tauri/`). To run it:

1. Install Rust (https://rustup.rs) — `rustc --version` should work in your terminal.
2. Run the app:
   ```bash
   pnpm tauri:dev      # dev, with hot-reload frontend
   pnpm tauri:build    # packaged binary
   ```

In the desktop app, scans use the **real engine** instead of the simulator:

- Pure-Rust concurrent TCP port scanner
- External tools — **nmap**, **nuclei**, **trivy** — auto-detected on `PATH`
  (and WinGet package dirs on Windows). Install whichever you want; Spectra runs
  what's available and enriches their output into the shared `Finding` model.
- Native HTTP banner/header probe (reqwest)
- Ollama co-pilot, proxied through Rust (no CORS)

### How it's wired

The frontend types in `src/types.ts` (`Finding`, `Scan`, …) are the IPC contract
the Rust side fulfils. Commands live in `src-tauri/src/lib.rs`; the typed bridge
that calls them is `src/lib/tauri.ts`. Security posture: a strict CSP, no
shell-plugin surface (process execution is native Rust, not exposed to the
webview), and scan-target validation against argument injection.

## Safety & Ethics

Spectra is a tool for **authorized** security assessments, red teaming, purple teaming, and defensive engineering only.

- Never scan targets without explicit written permission.
- Default to passive / read-only techniques where possible.
- All actions against targets are performed locally and logged.

## Roadmap

- OSV-scanner + SBOM import; dependency-risk and cloud-misconfig modules
- Advanced plugin system (YAML + WASM + native)
- Scheduled / continuous scanning mode
- PDF + HTML executive-summary export; Jira/Linear ticket creation
- Signed, packaged builds for Windows, macOS, Linux (system tray, native menus)
- False-positive reduction heuristics + local-model scoring

## Contributing

PRs welcome. Before opening one: `pnpm build && pnpm lint && pnpm test`, and for
Rust changes `cargo test` in `src-tauri/`. Keep simulated and real data clearly
distinguished, and keep the security posture intact (CSP, no shell-plugin
surface, target validation).

---

Built with ❤️ for people who are tired of mediocre scanner UIs and checkbox outputs.
