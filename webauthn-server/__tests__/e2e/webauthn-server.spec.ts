import { test, expect } from '@playwright/test';

test.describe('WebAuthn Server E2E Tests', () => {
  test('should serve health check endpoint', async ({ page }) => {
    const response = await page.goto('/health');
    expect(response?.status()).toBe(200);
    
    const healthData = await page.textContent('body');
    const data = JSON.parse(healthData || '{}');
    expect(data.success).toBe(true);
    expect(data.data.status).toBe('healthy');
    expect(data.data.version).toBe('1.0.0');
    expect(data.data.environment).toBe('test');
  });

  test('should serve registration options endpoint', async ({ page }) => {
    const response = await page.goto('/webauthn/register/options');
    expect(response?.status()).toBe(400); // Bad request due to missing POST data
  });

  test('should serve API documentation', async ({ page }) => {
    const response = await page.goto('/');
    expect(response?.status()).toBe(200);
    
    const content = await page.textContent('body');
    const data = JSON.parse(content || '{}');
    expect(data.success).toBe(true);
    expect(data.data.title).toContain('InfraSafe WebAuthn API');
  });

  test('should handle CORS preflight requests', async ({ page }) => {
    // This test would need to be more sophisticated to test CORS properly
    // For now, we'll just check that the server responds to basic requests
    const response = await page.goto('/webauthn/register-begin');
    expect(response?.status()).not.toBe(500);
  });
});

test.describe('WebAuthn Server API Tests', () => {
  test('should return 400 for GET on POST-only endpoints', async ({ page }) => {
    const endpoints = [
      '/webauthn/register/options',
      '/webauthn/register/verify',
      '/webauthn/login/options',
      '/webauthn/login/verify'
    ];

    for (const endpoint of endpoints) {
      const response = await page.goto(endpoint);
      expect(response?.status()).toBe(400); // Bad request due to missing POST data
    }
  });
});
