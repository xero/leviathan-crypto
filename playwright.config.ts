import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: 'test/e2e',
	outputDir: 'test/e2e/results',
  projects: [
    { name: 'chromium', use: { browserName: 'chromium' } },
    { name: 'firefox',  use: { browserName: 'firefox'  } },
    { name: 'webkit',   use: { browserName: 'webkit'   } },
  ],
  webServer: {
    command: 'bunx serve -l 1337 . || npx --yes serve -l 1337 .',
    url: 'http://localhost:1337',
    reuseExistingServer: true,
    timeout: 30_000,
  },
  timeout: 120_000,
})
