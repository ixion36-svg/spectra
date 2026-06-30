// Centralised, typed Tauri bridge. The web build stays fully independent:
// nothing here imports @tauri-apps/* at module load — APIs are lazy-loaded only
// inside a real Tauri webview.
import type { Scan, ScanEvent, ToolStatus } from '../types'

export const isTauriEnv =
  typeof window !== 'undefined' && (window as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ !== undefined

type InvokeFn = <T = unknown>(cmd: string, args?: Record<string, unknown>) => Promise<T>
type ListenFn = <T = unknown>(event: string, handler: (e: { payload: T }) => void) => Promise<() => void>

let invokeFn: InvokeFn | null = null
let listenFn: ListenFn | null = null
let loadPromise: Promise<void> | null = null

async function ensureApi(): Promise<void> {
  if (!isTauriEnv) return
  if (invokeFn) return
  if (!loadPromise) {
    loadPromise = (async () => {
      try {
        const [core, event] = await Promise.all([
          import('@tauri-apps/api/core'),
          import('@tauri-apps/api/event'),
        ])
        invokeFn = core.invoke as InvokeFn
        listenFn = event.listen as ListenFn
      } catch (e) {
        console.warn('Tauri APIs not available', e)
      }
    })()
  }
  await loadPromise
}

async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  await ensureApi()
  if (!invokeFn) throw new Error(`Tauri command ${cmd} called outside a Tauri webview`)
  return invokeFn<T>(cmd, args)
}

// ── Command wrappers (argument shapes match the Rust #[tauri::command] params) ─

export function detectInstalledTools(): Promise<ToolStatus[]> {
  return invoke<ToolStatus[]>('detect_installed_tools')
}

export function loadScans(): Promise<Scan[]> {
  return invoke<Scan[]>('load_scans')
}

export function saveScan(scan: Scan): Promise<void> {
  return invoke<void>('save_scan', { scan })
}

export function deleteScan(id: string): Promise<void> {
  return invoke<void>('delete_scan', { id })
}

export function tcpPortScan(scanId: string, host: string, ports: number[], concurrency = 80): Promise<unknown[]> {
  return invoke<unknown[]>('tcp_port_scan', { scanId, host, ports, concurrency })
}

export function runExternalScan(scanId: string, tool: string, target: string, extraArgs: string[] = []): Promise<unknown> {
  return invoke('run_external_scan', { scanId, tool, target, extraArgs })
}

export function httpProbe(target: string): Promise<Record<string, unknown>> {
  return invoke<Record<string, unknown>>('http_probe', { target })
}

/** Match a service banner against the CVE store; emits a finding per CVE onto
 *  the scan-event stream. Returns the number emitted. */
export function cveScanBanner(scanId: string, asset: string, banner: string): Promise<number> {
  return invoke<number>('cve_scan_banner', { scanId, asset, banner })
}

export interface CveMatch {
  cve_id: string
  product: string
  cvss?: number | null
  severity?: string | null
  summary?: string | null
  known_exploited: boolean
  ransomware: boolean
}

/** CVE store stats: how many CVE rows + KEV entries are loaded. */
export function cveStats(): Promise<{ cve_rows: number; kev_entries: number }> {
  return invoke<{ cve_rows: number; kev_entries: number }>('cve_stats')
}

/** Look up CVEs for a product + version against the local store. */
export function matchServiceCves(product: string, version: string): Promise<CveMatch[]> {
  return invoke<CveMatch[]>('match_service_cves', { product, version })
}

/** Fetch + import the latest CISA KEV catalog. Returns entries loaded. */
export function updateKevFeed(): Promise<number> {
  return invoke<number>('update_kev_feed')
}

export function cancelRealScan(scanId: string): Promise<void> {
  return invoke<void>('cancel_real_scan', { scanId })
}

export interface PluginInfo {
  id: string
  name: string
  severity: string
  path: string
}

/** List installed YAML check plugins. */
export function listPlugins(): Promise<PluginInfo[]> {
  return invoke<PluginInfo[]>('list_plugins')
}

/** Run all installed plugin checks against a target; returns the match count. */
export function runPluginChecks(scanId: string, target: string): Promise<number> {
  return invoke<number>('run_plugin_checks', { scanId, target })
}

/** Generate text via the local Ollama model, proxied through Rust (no CORS,
 *  no external connect-src). Returns the model's response string. */
export function ollamaGenerate(prompt: string, model: string, endpoint: string): Promise<string> {
  return invoke<string>('ollama_generate', { prompt, model, endpoint })
}

/** List models installed in the local Ollama instance (proxied through Rust). */
export function ollamaModels(endpoint: string): Promise<string[]> {
  return invoke<string[]>('ollama_models', { endpoint })
}

/** Stream a generation, invoking onToken for each chunk as it arrives.
 *  Resolves when the stream completes. */
export async function ollamaGenerateStream(
  prompt: string,
  model: string,
  endpoint: string,
  onToken: (token: string) => void,
): Promise<void> {
  await ensureApi()
  if (!invokeFn) throw new Error('ollama_generate_stream called outside a Tauri webview')
  const core = await import('@tauri-apps/api/core')
  const channel = new core.Channel<string>()
  channel.onmessage = onToken
  await invokeFn('ollama_generate_stream', { prompt, model, endpoint, onToken: channel })
}

export async function listenScanEvents(handler: (e: ScanEvent) => void): Promise<() => void> {
  await ensureApi()
  if (!listenFn) return () => {}
  return listenFn<ScanEvent>('scan-event', (event) => handler(event.payload))
}
