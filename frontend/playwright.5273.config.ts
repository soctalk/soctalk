import base from './playwright.config';
import { defineConfig } from '@playwright/test';
export default defineConfig({ ...base,
  use: { ...base.use, baseURL: 'http://localhost:5273' },
  webServer: { command: 'pnpm exec vite dev --port 5273 --strictPort', url: 'http://localhost:5273', reuseExistingServer: true, timeout: 120000 },
});
