import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { JWTPayload, AuthSession, User, UserDevice, AuthenticationError } from '../types';
import { config } from '../utils/config';
import { logger } from '../utils/logger';
import { storageService } from './storage';

/**
 * JWT service for handling authentication tokens and sessions
 */
class JWTService {
  private readonly secret = config.jwtSecret;
  private readonly expiresIn = config.jwtExpiresIn;
  private readonly sessionTimeout = config.sessionTimeout;

  constructor() {
    if (!this.secret) {
      throw new Error('JWT secret is required');
    }
  }

  /**
   * Create a new session and generate JWT token
   */
  async createSession(
    user: User,
    device: UserDevice,
    ipAddress: string,
    userAgent: string
  ): Promise<{ token: string; session: AuthSession }> {
    try {
      const sessionId = uuidv4();
      const now = new Date();
      const expiresAt = new Date(now.getTime() + this.sessionTimeout);

      // Create session record
      const session: AuthSession = {
        sessionId,
        userId: user.id,
        walletAddress: user.walletAddress,
        issuedAt: now,
        expiresAt,
        deviceId: device.id,
        ipAddress,
        userAgent,
      };

      // Save session
      await storageService.createSession(session);

      // Create JWT payload
      const payload: JWTPayload = {
        userId: user.id,
        walletAddress: user.walletAddress,
        sessionId,
        deviceId: device.id,
        iat: Math.floor(now.getTime() / 1000),
        exp: Math.floor(expiresAt.getTime() / 1000),
      };

      // Sign JWT
      const token = jwt.sign(payload, this.secret, {
        algorithm: 'HS256',
        issuer: 'infrasafe-webauthn',
        audience: 'infrasafe-client',
      });

      logger.auth('Session created', {
        sessionId,
        userId: user.id,
        walletAddress: user.walletAddress,
        deviceId: device.id,
        ipAddress,
        expiresAt,
      });

      return { token, session };
    } catch (error) {
      logger.error('Failed to create session', {
        userId: user.id,
        deviceId: device.id,
        error: error instanceof Error ? error.message : error,
      });
      throw new AuthenticationError('Failed to create session', 'SESSION_CREATION_FAILED');
    }
  }

  /**
   * Verify and decode JWT token
   */
  async verifyToken(token: string): Promise<JWTPayload> {
    try {
      const decoded = jwt.verify(token, this.secret, {
        algorithms: ['HS256'],
        issuer: 'infrasafe-webauthn',
        audience: 'infrasafe-client',
      }) as JWTPayload;

      return decoded;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new AuthenticationError('Token expired', 'TOKEN_EXPIRED', 401);
      } else if (error instanceof jwt.JsonWebTokenError) {
        throw new AuthenticationError('Invalid token', 'INVALID_TOKEN', 401);
      } else {
        logger.error('Token verification error', {
          error: error instanceof Error ? error.message : error,
        });
        throw new AuthenticationError('Token verification failed', 'TOKEN_VERIFICATION_FAILED', 401);
      }
    }
  }

  /**
   * Validate session and return session data
   */
  async validateSession(token: string): Promise<{ 
    user: User; 
    session: AuthSession; 
    payload: JWTPayload 
  }> {
    try {
      // Verify JWT
      const payload = await this.verifyToken(token);

      // Get session from storage
      const session = await storageService.getSession(payload.sessionId);
      if (!session) {
        throw new AuthenticationError('Session not found', 'SESSION_NOT_FOUND', 401);
      }

      // Check if session is expired
      if (session.expiresAt <= new Date()) {
        await storageService.removeSession(session.sessionId);
        throw new AuthenticationError('Session expired', 'SESSION_EXPIRED', 401);
      }

      // Verify session data matches JWT
      if (
        session.userId !== payload.userId ||
        session.walletAddress !== payload.walletAddress ||
        session.deviceId !== payload.deviceId
      ) {
        logger.security('Session data mismatch', {
          sessionId: session.sessionId,
          jwtUserId: payload.userId,
          sessionUserId: session.userId,
          jwtWallet: payload.walletAddress,
          sessionWallet: session.walletAddress,
        });
        throw new AuthenticationError('Session data mismatch', 'SESSION_DATA_MISMATCH', 401);
      }

      // Get user
      const user = await storageService.getUserById(session.userId);
      if (!user) {
        throw new AuthenticationError('User not found', 'USER_NOT_FOUND', 401);
      }

      logger.debug('Session validated', {
        sessionId: session.sessionId,
        userId: user.id,
        walletAddress: user.walletAddress,
      });

      return { user, session, payload };
    } catch (error) {
      if (error instanceof AuthenticationError) {
        throw error;
      }

      logger.error('Session validation error', {
        error: error instanceof Error ? error.message : error,
      });
      throw new AuthenticationError('Session validation failed', 'SESSION_VALIDATION_FAILED', 401);
    }
  }

  /**
   * Refresh a session (extend expiration)
   */
  async refreshSession(token: string): Promise<{ token: string; session: AuthSession }> {
    try {
      const { user, session } = await this.validateSession(token);

      // Get device
      const device = await storageService.getDeviceById(session.deviceId);
      if (!device) {
        throw new AuthenticationError('Device not found', 'DEVICE_NOT_FOUND', 401);
      }

      // Remove old session
      await storageService.removeSession(session.sessionId);

      // Create new session
      const newSession = await this.createSession(
        user,
        device,
        session.ipAddress,
        session.userAgent
      );

      logger.auth('Session refreshed', {
        oldSessionId: session.sessionId,
        newSessionId: newSession.session.sessionId,
        userId: user.id,
      });

      return newSession;
    } catch (error) {
      if (error instanceof AuthenticationError) {
        throw error;
      }

      logger.error('Session refresh error', {
        error: error instanceof Error ? error.message : error,
      });
      throw new AuthenticationError('Session refresh failed', 'SESSION_REFRESH_FAILED', 401);
    }
  }

  /**
   * Invalidate a session
   */
  async invalidateSession(sessionId: string): Promise<void> {
    try {
      await storageService.removeSession(sessionId);
      
      logger.auth('Session invalidated', { sessionId });
    } catch (error) {
      logger.error('Session invalidation error', {
        sessionId,
        error: error instanceof Error ? error.message : error,
      });
      throw new AuthenticationError('Session invalidation failed', 'SESSION_INVALIDATION_FAILED');
    }
  }

  /**
   * Invalidate all user sessions
   */
  async invalidateAllUserSessions(userId: string): Promise<void> {
    try {
      await storageService.removeAllUserSessions(userId);
      
      logger.auth('All user sessions invalidated', { userId });
    } catch (error) {
      logger.error('User session invalidation error', {
        userId,
        error: error instanceof Error ? error.message : error,
      });
      throw new AuthenticationError('User session invalidation failed', 'USER_SESSION_INVALIDATION_FAILED');
    }
  }

  /**
   * Extract token from Authorization header
   */
  extractTokenFromHeader(authHeader: string): string | null {
    if (!authHeader) {
      return null;
    }

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      return null;
    }

    return parts[1];
  }

  /**
   * Generate a temporary token for specific operations
   */
  generateTemporaryToken(
    userId: string,
    purpose: string,
    expiresInMinutes: number = 15
  ): string {
    const payload = {
      userId,
      purpose,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (expiresInMinutes * 60),
    };

    return jwt.sign(payload, this.secret, {
      algorithm: 'HS256',
      issuer: 'infrasafe-webauthn',
      audience: 'infrasafe-temp',
    });
  }

  /**
   * Verify temporary token
   */
  verifyTemporaryToken(token: string, expectedPurpose: string): { userId: string } {
    try {
      const decoded = jwt.verify(token, this.secret, {
        algorithms: ['HS256'],
        issuer: 'infrasafe-webauthn',
        audience: 'infrasafe-temp',
      }) as any;

      if (decoded.purpose !== expectedPurpose) {
        throw new AuthenticationError('Invalid token purpose', 'INVALID_TOKEN_PURPOSE', 401);
      }

      return { userId: decoded.userId };
    } catch (error) {
      if (error instanceof AuthenticationError) {
        throw error;
      }

      logger.error('Temporary token verification error', {
        expectedPurpose,
        error: error instanceof Error ? error.message : error,
      });
      throw new AuthenticationError('Invalid temporary token', 'INVALID_TEMPORARY_TOKEN', 401);
    }
  }

  /**
   * Health check for JWT service
   */
  healthCheck(): { jwt: boolean; config: boolean } {
    return {
      jwt: !!this.secret,
      config: !!(this.secret && this.expiresIn),
    };
  }
}

export const jwtService = new JWTService();
