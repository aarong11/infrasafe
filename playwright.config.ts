import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './webauthn-server/__tests__/e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'html',
  use: {
    baseURL: 'http://localhost:3001',
    trace: 'on-first-retry',
  },

  projects: [
    {
      name: 'chromium',
      use: { 
        ...devices['Desktop Chrome'],
        // Enable WebAuthn virtual authenticator
        launchOptions: {
          args: ['--enable-features=WebAuthenticationRemoteDesktopSupport']
        }
      },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
  ],

  webServer: {
    command: './scripts/start-webauthn-test.sh',
    url: 'http://localhost:3001',
    reuseExistingServer: !process.env.CI,
  },
});
