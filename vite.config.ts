import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  // Tauri expects a fixed port in development.
  // Bind to loopback only: the dev app proxies to the local Ollama instance,
  // so exposing it on 0.0.0.0 would put that on the LAN. Set host to a LAN IP
  // explicitly only when you intentionally need mobile/remote dev.
  server: {
    port: 5173,
    strictPort: true,
    host: '127.0.0.1',
  },
  // Prevent vite from clearing the terminal when running tauri dev
  clearScreen: false,
})
