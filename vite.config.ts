import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  // Tauri expects a fixed port in development
  server: {
    port: 5173,
    strictPort: true,
    host: '0.0.0.0',
  },
  // Prevent vite from clearing the terminal when running tauri dev
  clearScreen: false,
})
