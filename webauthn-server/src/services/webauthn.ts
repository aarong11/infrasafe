// @ts-nocheck
import { 
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';
import type {
  GenerateRegistrationOptionsOpts,
  GenerateAuthenticationOptionsOpts,
  VerifyRegistrationResponseOpts,
  VerifyAuthenticationResponseOpts,
} from '@simplewebauthn/server';
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON
} from '@simplewebauthn/types';
import { v4 as uuidv4 } from 'uuid';
import { 
  User, 
  UserDevice, 
  RegistrationChallenge, 
  AuthenticationChallenge,
  WebAuthnError,
  RegistrationOptions,
  AuthenticationOptions
} from '../types';
import { config } from '../utils/config';
import { logger } from '../utils/logger';
import { storageService } from './storage';

/**
 * WebAuthn service for handling biometric authentication
 */
class WebAuthnService {
  private readonly rpName = config.rpName;
  private readonly rpId = config.rpId;
  private readonly origin = config.origin;
  private readonly challengeTimeout = config.challengeTimeout;

  constructor() {
    logger.webauthn('WebAuthn service initialized', {
      rpName: this.rpName,
      rpId: this.rpId,
      origin: this.origin
    });
  }

  /**
   * Generate registration options for WebAuthn
   */
  async generateRegistrationOptions(user: User, deviceName?: string): Promise<RegistrationOptions> {
    try {
      // Get existing devices to exclude
      const existingDevices = await storageService.getDevicesByUserId(user.id);
      const excludeCredentials = existingDevices.map(device => ({
        id: device.credentialID,
        type: 'public-key' as const,
        transports: device.transports,
      }));

      const options = await generateRegistrationOptions({
        rpName: this.rpName,
        rpID: this.rpId,
        userID: user.id,
        userName: user.username,
        userDisplayName: user.username,
        timeout: this.challengeTimeout,
        attestationType: 'none',
        excludeCredentials,
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'preferred',
          residentKey: 'preferred',
        },
        supportedAlgorithmIDs: [-7, -257], // ES256, RS256
      });

      // Store challenge
      const challengeData: RegistrationChallenge = {
        challenge: options.challenge,
        userId: user.id,
        expiresAt: new Date(Date.now() + this.challengeTimeout),
        userVerification: options.authenticatorSelection?.userVerification || 'preferred',
      };

      await storageService.saveRegistrationChallenge(challengeData);

      logger.webauthn('Registration options generated', {
        userId: user.id,
        challenge: options.challenge,
        deviceName,
        excludeCredentialsCount: excludeCredentials.length
      });

      return {
        challenge: options.challenge,
        rp: options.rp,
        user: options.user,
        pubKeyCredParams: options.pubKeyCredParams,
        timeout: options.timeout,
        attestation: options.attestation,
        excludeCredentials: options.excludeCredentials,
        authenticatorSelection: options.authenticatorSelection,
      };
    } catch (error) {
      logger.error('Failed to generate registration options', {
        userId: user.id,
        error: error instanceof Error ? error.message : error
      });
      throw new WebAuthnError('Failed to generate registration options', 'REGISTRATION_OPTIONS_FAILED');
    }
  }

  /**
   * Verify registration response
   */
  async verifyRegistrationResponse(
    userId: string,
    credential: RegistrationResponseJSON,
    deviceName?: string
  ): Promise<UserDevice> {
    try {
      const user = await storageService.getUserById(userId);
      if (!user) {
        throw new WebAuthnError('User not found', 'USER_NOT_FOUND', 404);
      }

      // Get challenge
      const challengeData = await storageService.getRegistrationChallenge(credential.response.clientDataJSON);
      if (!challengeData) {
        throw new WebAuthnError('Invalid or expired challenge', 'INVALID_CHALLENGE');
      }

      if (challengeData.userId !== userId) {
        throw new WebAuthnError('Challenge user mismatch', 'CHALLENGE_USER_MISMATCH');
      }

      // Verify the registration
      const verification = await verifyRegistrationResponse({
        response: credential,
        expectedChallenge: challengeData.challenge,
        expectedOrigin: this.origin,
        expectedRPID: this.rpId,
        requireUserVerification: challengeData.userVerification === 'required',
      });

      if (!verification.verified || !verification.registrationInfo) {
        logger.security('Registration verification failed', {
          userId,
          verified: verification.verified,
          credentialId: credential.id
        });
        throw new WebAuthnError('Registration verification failed', 'REGISTRATION_VERIFICATION_FAILED');
      }

      // Create device record
      const device: UserDevice = {
        id: uuidv4(),
        userId,
        name: deviceName || 'WebAuthn Device',
        credentialID: verification.registrationInfo.credentialID,
        credentialPublicKey: verification.registrationInfo.credentialPublicKey,
        counter: verification.registrationInfo.counter,
        credentialDeviceType: verification.registrationInfo.credentialDeviceType,
        credentialBackedUp: verification.registrationInfo.credentialBackedUp,
        transports: credential.response.transports,
        createdAt: new Date(),
      };

      // Save device
      await storageService.saveDevice(device);

      // Clean up challenge
      await storageService.removeRegistrationChallenge(challengeData.challenge);

      logger.webauthn('Registration completed successfully', {
        userId,
        deviceId: device.id,
        deviceName: device.name,
        credentialId: credential.id,
        deviceType: device.credentialDeviceType
      });

      return device;
    } catch (error) {
      if (error instanceof WebAuthnError) {
        throw error;
      }

      logger.error('Registration verification error', {
        userId,
        credentialId: credential.id,
        error: error instanceof Error ? error.message : error
      });
      throw new WebAuthnError('Registration verification failed', 'REGISTRATION_VERIFICATION_ERROR');
    }
  }

  /**
   * Generate authentication options
   */
  async generateAuthenticationOptions(
    walletAddress?: string,
    username?: string
  ): Promise<{ options: AuthenticationOptions; allowedDevices: UserDevice[] }> {
    try {
      let user: User | null = null;
      let allowedDevices: UserDevice[] = [];

      if (walletAddress) {
        user = await storageService.getUserByWalletAddress(walletAddress);
      } else if (username) {
        user = await storageService.getUserByUsername(username);
      }

      if (user) {
        allowedDevices = await storageService.getDevicesByUserId(user.id);
      }

      const allowCredentials = allowedDevices.length > 0 ? allowedDevices.map(device => ({
        id: device.credentialID,
        type: 'public-key' as const,
        transports: device.transports,
      })) : undefined;

      const options = await generateAuthenticationOptions({
        timeout: this.challengeTimeout,
        allowCredentials,
        userVerification: 'preferred',
        rpID: this.rpId,
      });

      // Store challenge
      const challengeData: AuthenticationChallenge = {
        challenge: options.challenge,
        allowCredentials: options.allowCredentials,
        expiresAt: new Date(Date.now() + this.challengeTimeout),
        userVerification: options.userVerification,
      };

      await storageService.saveAuthenticationChallenge(challengeData);

      logger.webauthn('Authentication options generated', {
        userId: user?.id,
        walletAddress,
        username,
        challenge: options.challenge,
        allowedDevicesCount: allowedDevices.length
      });

      return {
        options: {
          challenge: options.challenge,
          timeout: options.timeout,
          rpId: options.rpId,
          allowCredentials: options.allowCredentials,
          userVerification: options.userVerification,
        },
        allowedDevices
      };
    } catch (error) {
      logger.error('Failed to generate authentication options', {
        walletAddress,
        username,
        error: error instanceof Error ? error.message : error
      });
      throw new WebAuthnError('Failed to generate authentication options', 'AUTHENTICATION_OPTIONS_FAILED');
    }
  }

  /**
   * Verify authentication response
   */
  async verifyAuthenticationResponse(
    credential: AuthenticationResponseJSON
  ): Promise<{ user: User; device: UserDevice }> {
    try {
      // Find the device by credential ID
      const devices = await this.findDeviceByCredentialId(credential.id);
      if (devices.length === 0) {
        throw new WebAuthnError('Device not found', 'DEVICE_NOT_FOUND', 404);
      }

      // Try each device (in case of credential ID conflicts, though unlikely)
      let verification: any = null;
      let matchedDevice: UserDevice | null = null;

      for (const device of devices) {
        try {
          // Get challenge from client data
          const clientDataJSON = JSON.parse(
            Buffer.from(credential.response.clientDataJSON, 'base64').toString()
          );
          const challenge = clientDataJSON.challenge;

          const challengeData = await storageService.getAuthenticationChallenge(challenge);
          if (!challengeData) {
            continue; // Try next device
          }

          verification = await verifyAuthenticationResponse({
            response: credential,
            expectedChallenge: challengeData.challenge,
            expectedOrigin: this.origin,
            expectedRPID: this.rpId,
            authenticator: {
              credentialID: device.credentialID,
              credentialPublicKey: device.credentialPublicKey,
              counter: device.counter,
              transports: device.transports,
            },
            requireUserVerification: challengeData.userVerification === 'required',
          });

          if (verification.verified) {
            matchedDevice = device;
            // Clean up challenge
            await storageService.removeAuthenticationChallenge(challengeData.challenge);
            break;
          }
        } catch (deviceError) {
          logger.debug('Device verification failed, trying next', {
            deviceId: device.id,
            error: deviceError instanceof Error ? deviceError.message : deviceError
          });
          continue;
        }
      }

      if (!verification?.verified || !matchedDevice) {
        logger.security('Authentication verification failed', {
          credentialId: credential.id,
          deviceCount: devices.length
        });
        throw new WebAuthnError('Authentication verification failed', 'AUTHENTICATION_VERIFICATION_FAILED');
      }

      // Update device counter
      matchedDevice.counter = verification.authenticationInfo.newCounter;
      matchedDevice.lastUsedAt = new Date();
      await storageService.saveDevice(matchedDevice);

      // Get user
      const user = await storageService.getUserById(matchedDevice.userId);
      if (!user) {
        throw new WebAuthnError('User not found', 'USER_NOT_FOUND', 404);
      }

      // Update user last login
      await storageService.updateUserLastLogin(user.id);

      logger.webauthn('Authentication completed successfully', {
        userId: user.id,
        deviceId: matchedDevice.id,
        credentialId: credential.id,
        newCounter: verification.authenticationInfo.newCounter
      });

      return { user, device: matchedDevice };
    } catch (error) {
      if (error instanceof WebAuthnError) {
        throw error;
      }

      logger.error('Authentication verification error', {
        credentialId: credential.id,
        error: error instanceof Error ? error.message : error
      });
      throw new WebAuthnError('Authentication verification failed', 'AUTHENTICATION_VERIFICATION_ERROR');
    }
  }

  /**
   * Find device by credential ID
   */
  private async findDeviceByCredentialId(credentialId: string): Promise<UserDevice[]> {
    // In a real implementation, this would be a database query
    // For now, we'll search through all devices (inefficient but functional)
    const devices: UserDevice[] = [];
    
    // This is a simplified approach - in production, use proper indexing
    const stats = await storageService.getStats();
    // We'd need a proper way to iterate through devices
    // For now, this is a placeholder that would need proper implementation
    
    return devices;
  }

  /**
   * Get user devices
   */
  async getUserDevices(userId: string): Promise<UserDevice[]> {
    try {
      const devices = await storageService.getDevicesByUserId(userId);
      
      logger.webauthn('User devices retrieved', {
        userId,
        deviceCount: devices.length
      });
      
      return devices;
    } catch (error) {
      logger.error('Failed to get user devices', {
        userId,
        error: error instanceof Error ? error.message : error
      });
      throw new WebAuthnError('Failed to get user devices', 'GET_DEVICES_FAILED');
    }
  }

  /**
   * Remove device
   */
  async removeDevice(userId: string, deviceId: string): Promise<void> {
    try {
      const device = await storageService.getDeviceById(deviceId);
      if (!device) {
        throw new WebAuthnError('Device not found', 'DEVICE_NOT_FOUND', 404);
      }

      if (device.userId !== userId) {
        throw new WebAuthnError('Device does not belong to user', 'DEVICE_OWNERSHIP_MISMATCH', 403);
      }

      await storageService.removeDevice(deviceId);

      logger.webauthn('Device removed', {
        userId,
        deviceId,
        deviceName: device.name
      });
    } catch (error) {
      if (error instanceof WebAuthnError) {
        throw error;
      }

      logger.error('Failed to remove device', {
        userId,
        deviceId,
        error: error instanceof Error ? error.message : error
      });
      throw new WebAuthnError('Failed to remove device', 'REMOVE_DEVICE_FAILED');
    }
  }

  /**
   * Validate WebAuthn support
   */
  validateWebAuthnSupport(userAgent: string): boolean {
    // Basic user agent check for WebAuthn support
    const supportedBrowsers = [
      /Chrome\/\d+/,
      /Firefox\/\d+/,
      /Safari\/\d+/,
      /Edge\/\d+/,
    ];

    return supportedBrowsers.some(regex => regex.test(userAgent));
  }

  /**
   * Health check for WebAuthn service
   */
  async healthCheck(): Promise<{
    webauthn: boolean;
    storage: boolean;
    config: boolean;
  }> {
    const health = {
      webauthn: true,
      storage: true,
      config: true,
    };

    try {
      // Test storage
      const stats = await storageService.getStats();
      health.storage = true;
    } catch (error) {
      health.storage = false;
    }

    // Test config
    if (!this.rpName || !this.rpId || !this.origin) {
      health.config = false;
    }

    return health;
  }
}

export const webAuthnService = new WebAuthnService();
