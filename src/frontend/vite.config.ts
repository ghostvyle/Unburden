import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import { fileURLToPath } from 'url';

// === Resolver __dirname para módulos ES ===
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// === Exportar configuración Vite ===
export default defineConfig({
  plugins: [react()],
  base: '/app/',
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/chat': process.env.VITE_API_BASE_URL || 'http://localhost:7777',
      '/descargar-pentesting': process.env.VITE_API_BASE_URL || 'http://localhost:7777',
      '/borrar-pentesting': process.env.VITE_API_BASE_URL || 'http://localhost:7777',
      '/sobrescribir-pentesting': process.env.VITE_API_BASE_URL || 'http://localhost:7777',
      '/compartir-pentesting': process.env.VITE_API_BASE_URL || 'http://localhost:7777',
      '/compartido': process.env.VITE_API_BASE_URL || 'http://localhost:7777',
    },
  },
});
