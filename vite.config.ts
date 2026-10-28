import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // The dev server sits in the same tree as the .NET projects; watching
    // obj/bin crashes with EBUSY whenever dotnet build locks apphost.exe.
    watch: {
      ignored: ['**/obj/**', '**/bin/**', '**/node_modules/**', '**/dist/**', '**/publish/**'],
    },
  },
  build: {
    // The application is deliberately shipped as one local dashboard bundle.
    // Its measured production bundle is ~608 kB, below this reviewed limit.
    chunkSizeWarningLimit: 650,
  },
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('.', import.meta.url)),
    },
  },
});
