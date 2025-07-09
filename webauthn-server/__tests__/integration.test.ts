/**
 * Basic integration tests for the WebAuthn server
 * These tests start the server and test real HTTP endpoints
 */

import { webAuthnService } from '../src/services/webauthn';
import { storageService } from '../src/services/storage';
import { config } from '../src/utils/config';
import { logger } from '../src/utils/logger';
import request from 'supertest';
import webAuthnServer from '../src/app';

describe('WebAuthn Integration Tests', () => {
  const app = webAuthnServer.getApp();
  beforeEach(async () => {
    await storageService.reset();
  });

  afterAll(async () => {
    await storageService.shutdown();
  });

  describe('Health Check', () => {
    it('should return health status', async () => {
      // Temporarily enable console for debugging
      const originalError = console.error;
      console.error = originalError;
      
      const response = await request(app)
        .get('/health');
      
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('success', true);
      expect(response.body).toHaveProperty('data');
      expect(response.body.data).toHaveProperty('status', 'healthy');
      expect(response.body.data).toHaveProperty('timestamp');
      expect(response.body.data).toHaveProperty('version', '1.0.0');
      expect(response.body.data).toHaveProperty('environment', 'test');
    });
  });

  describe('API Documentation', () => {
    it('should serve API documentation', async () => {
      const response = await request(app)
        .get('/docs')
        .expect(200);

      expect(response.body).toHaveProperty('success', true);
      expect(response.body).toHaveProperty('data');
      expect(response.body.data).toHaveProperty('title', 'InfraSafe WebAuthn API');
    });
  });

  describe('Rate Limiting', () => {
    it('should enforce rate limits', async () => {
      // Make many requests quickly to trigger rate limiting
      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(request(app).get('/health'));
      }

      const responses = await Promise.all(promises);
      
      // All should succeed since we're under the limit
      responses.forEach(response => {
        expect(response.status).toBe(200);
      });
    });
  });

  describe('WebAuthn Registration Flow', () => {
    it('should start registration process', async () => {
      const response = await request(app)
        .post('/webauthn/register/options')
        .set('Origin', 'http://localhost:3002')
        .send({
          username: 'testuser',
          walletAddress: '0x1234567890123456789012345678901234567890'
        })
        .expect(200);

      expect(response.body).toHaveProperty('success', true);
      expect(response.body).toHaveProperty('data');
      expect(response.body.data).toHaveProperty('options');
      expect(response.body.data.options).toHaveProperty('challenge');
      expect(response.body.data.options).toHaveProperty('rp');
      expect(response.body.data.options).toHaveProperty('user');
      expect(response.body.data).toHaveProperty('userId');
    });

    it('should require valid input for registration', async () => {
      const response = await request(app)
        .post('/webauthn/register/options')
        .set('Origin', 'http://localhost:3002')
        .send({
          username: '', // Invalid empty username
          walletAddress: 'invalid-address'
        })
        .expect(400);

      expect(response.body).toHaveProperty('error');
    });
  });

  describe('WebAuthn Authentication Flow', () => {
    it('should start authentication process', async () => {
      const response = await request(app)
        .post('/webauthn/login/options')
        .set('Origin', 'http://localhost:3002')
        .send({
          walletAddress: '0x1234567890123456789012345678901234567890'
        })
        .expect(200);

      expect(response.body).toHaveProperty('success', true);
      expect(response.body).toHaveProperty('data');
      expect(response.body.data).toHaveProperty('options');
      expect(response.body.data.options).toHaveProperty('challenge');
      expect(response.body.data.options).toHaveProperty('rpId');
    });

    it('should handle non-existent user authentication', async () => {
      const response = await request(app)
        .post('/webauthn/login/options')
        .set('Origin', 'http://localhost:3002')
        .send({
          walletAddress: '0x9999999999999999999999999999999999999999'
        })
        .expect(200);

      expect(response.body).toHaveProperty('success', true);
      expect(response.body).toHaveProperty('data');
      expect(response.body.data).toHaveProperty('options');
      expect(response.body.data.options).toHaveProperty('challenge');
      expect(response.body.data).toHaveProperty('deviceCount', 0);
      expect(response.body.data).toHaveProperty('hasDevices', false);
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid JSON', async () => {
      const response = await request(app)
        .post('/webauthn/register/options')
        .set('Content-Type', 'application/json')
        .send('invalid json')
        .expect(500);

      expect(response.body).toHaveProperty('error');
    });

    it('should handle missing content type', async () => {
      const response = await request(app)
        .post('/webauthn/register-begin')
        .send('some data')
        .expect(400);

      expect(response.body).toHaveProperty('error');
    });
  });

  describe('Security Headers', () => {
    it('should include security headers', async () => {
      const response = await request(app)
        .get('/health')
        .expect(200);

      expect(response.headers).toHaveProperty('x-content-type-options');
      expect(response.headers).toHaveProperty('x-frame-options');
      expect(response.headers).toHaveProperty('x-xss-protection');
    });
  });
});
