/**
 * WebAuthn service tests
 */

import { webAuthnService } from '../src/services/webauthn';
import { storageService } from '../src/services/storage';
import { User } from '../src/types';

describe('WebAuthn Service', () => {
  let mockUser: User;

  beforeEach(() => {
    mockUser = {
      id: 'test-user-id',
      username: 'testuser',
      walletAddress: '0x1234567890123456789012345678901234567890',
      createdAt: new Date(),
    };
  });

  describe('generateRegistrationOptions', () => {
    it('should generate registration options for a new user', async () => {
      const options = await webAuthnService.generateRegistrationOptions(mockUser);

      expect(options).toHaveProperty('challenge');
      expect(options).toHaveProperty('rp');
      expect(options).toHaveProperty('user');
      expect(options).toHaveProperty('pubKeyCredParams');
      expect(options.rp.name).toBe('InfraSafe Test');
      expect(options.user.id).toBe(mockUser.id);
      expect(options.user.name).toBe(mockUser.username);
    });

    it('should exclude existing devices', async () => {
      // This test would need proper mocking of existing devices
      const options = await webAuthnService.generateRegistrationOptions(mockUser);
      expect(options.excludeCredentials).toBeDefined();
    });
  });

  describe('generateAuthenticationOptions', () => {
    it('should generate authentication options for existing user', async () => {
      await storageService.createUser(mockUser.username, mockUser.walletAddress);
      
      const { options } = await webAuthnService.generateAuthenticationOptions(
        mockUser.walletAddress
      );

      expect(options).toHaveProperty('challenge');
      expect(options).toHaveProperty('timeout');
      expect(options).toHaveProperty('rpId');
      expect(options.rpId).toBe('localhost');
    });

    it('should handle non-existent user', async () => {
      const { options, allowedDevices } = await webAuthnService.generateAuthenticationOptions(
        '0x9999999999999999999999999999999999999999'
      );

      expect(options).toHaveProperty('challenge');
      expect(allowedDevices).toHaveLength(0);
    });
  });

  describe('healthCheck', () => {
    it('should return health status', async () => {
      const health = await webAuthnService.healthCheck();

      expect(health).toHaveProperty('webauthn');
      expect(health).toHaveProperty('storage');
      expect(health).toHaveProperty('config');
      expect(health.webauthn).toBe(true);
      expect(health.storage).toBe(true);
      expect(health.config).toBe(true);
    });
  });

  describe('validateWebAuthnSupport', () => {
    it('should validate supported browsers', () => {
      expect(webAuthnService.validateWebAuthnSupport('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')).toBe(true);
      expect(webAuthnService.validateWebAuthnSupport('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')).toBe(true);
      expect(webAuthnService.validateWebAuthnSupport('Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0')).toBe(true);
    });

    it('should reject unsupported browsers', () => {
      expect(webAuthnService.validateWebAuthnSupport('Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)')).toBe(false);
      expect(webAuthnService.validateWebAuthnSupport('curl/7.68.0')).toBe(false);
    });
  });
});
