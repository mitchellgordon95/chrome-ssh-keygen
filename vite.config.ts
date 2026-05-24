import { defineConfig } from 'vite';
import { resolve } from 'path';
import { copyFileSync, writeFileSync } from 'fs';

export default defineConfig({
  build: {
    outDir: 'dist',
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'src/popup/index.html'),
      },
    },
  },
  plugins: [
    {
      name: 'copy-manifest-and-background',
      closeBundle() {
        copyFileSync(
          resolve(__dirname, 'manifest.json'),
          resolve(__dirname, 'dist/manifest.json'),
        );
        // Write a minimal background service worker
        writeFileSync(
          resolve(__dirname, 'dist/background.js'),
          '// MV3 service worker\n',
        );
      },
    },
  ],
  test: {
    globals: true,
    exclude: ['tests/e2e/**', 'node_modules/**'],
  },
});
