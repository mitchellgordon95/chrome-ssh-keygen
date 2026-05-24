import { defineConfig } from 'vite';
import { resolve } from 'path';
import { copyFileSync, writeFileSync, mkdirSync } from 'fs';

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
      name: 'copy-manifest-and-assets',
      closeBundle() {
        copyFileSync(
          resolve(__dirname, 'manifest.json'),
          resolve(__dirname, 'dist/manifest.json'),
        );
        writeFileSync(
          resolve(__dirname, 'dist/background.js'),
          '// MV3 service worker\n',
        );
        // Copy icons
        mkdirSync(resolve(__dirname, 'dist/icons'), { recursive: true });
        for (const size of ['icon16.png', 'icon48.png', 'icon128.png']) {
          copyFileSync(
            resolve(__dirname, 'icons', size),
            resolve(__dirname, 'dist/icons', size),
          );
        }
      },
    },
  ],
  test: {
    globals: true,
    exclude: ['tests/e2e/**', 'node_modules/**'],
  },
});
