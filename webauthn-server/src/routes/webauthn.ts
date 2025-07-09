import { Router, Request, Response } from 'express';
import { 
  RegistrationStartSchema,
  RegistrationFinishSchema,
  AuthenticationStartSchema,
  AuthenticationFinishSchema
} from '../utils/validation';
import { validateRequest, asyncHandler } from '../middleware/error';
import { authRateLimit, registrationRateLimit } from '../middleware/rateLimit';
import { validateWebAuthnOrigin, validateContentType } from '../middleware/security';
import { authenticate, optionalAuthenticate } from '../middleware/auth';
import { webAuthnService } from '../services/webauthn';
import { jwtService } from '../services/jwt';
import { storageService } from '../services/storage';
import { logger } from '../utils/logger';
import { ApiResponse, WebAuthnError } from '../types';

const router = Router();

// Apply common middleware
router.use(validateWebAuthnOrigin);
router.use(validateContentType());

/**
 * POST /webauthn/register/options
 * Generate registration options for WebAuthn
 */
router.post(
  '/register/options',
  registrationRateLimit,
  validateRequest(RegistrationStartSchema),
  asyncHandler(async (req: Request, res: Response) => {
    const { username, walletAddress, deviceName } = req.body;

    // Check if user already exists
    const existingUserByWallet = await storageService.getUserByWalletAddress(walletAddress);
    const existingUserByUsername = await storageService.getUserByUsername(username);

    if (existingUserByWallet || existingUserByUsername) {
      const response: ApiResponse = {
        success: false,
        error: 'User already exists with this wallet address or username',
      };
      res.status(409).json(response);
      return;
    }

    // Create temporary user
    const user = await storageService.createUser(username, walletAddress);

    // Generate registration options
    const options = await webAuthnService.generateRegistrationOptions(user, deviceName);

    logger.webauthn('Registration options generated', {
      userId: user.id,
      username,
      walletAddress,
      deviceName,
    });

    const response: ApiResponse = {
      success: true,
      data: {
        options,
        userId: user.id,
      },
    };

    res.json(response);
  })
);

/**
 * POST /webauthn/register/verify
 * Verify registration response
 */
router.post(
  '/register/verify',
  registrationRateLimit,
  validateRequest(RegistrationFinishSchema),
  asyncHandler(async (req: Request, res: Response) => {
    const { userId, credential, deviceName } = req.body;

    // Verify the registration
    const device = await webAuthnService.verifyRegistrationResponse(
      userId,
      credential,
      deviceName
    );

    // Get user
    const user = await storageService.getUserById(userId);
    if (!user) {
      throw new WebAuthnError('User not found', 'USER_NOT_FOUND', 404);
    }

    // Create session
    const { token, session } = await jwtService.createSession(
      user,
      device,
      req.ip || 'unknown',
      req.get('User-Agent') || 'unknown'
    );

    logger.webauthn('Registration completed and session created', {
      userId: user.id,
      deviceId: device.id,
      sessionId: session.sessionId,
    });

    const response: ApiResponse = {
      success: true,
      data: {
        user: {
          id: user.id,
          username: user.username,
          walletAddress: user.walletAddress,
          createdAt: user.createdAt,
        },
        device: {
          id: device.id,
          name: device.name,
          createdAt: device.createdAt,
        },
        token,
        expiresAt: session.expiresAt,
      },
    };

    res.status(201).json(response);
  })
);

/**
 * POST /webauthn/login/options
 * Generate authentication options
 */
router.post(
  '/login/options',
  authRateLimit,
  validateRequest(AuthenticationStartSchema),
  asyncHandler(async (req: Request, res: Response) => {
    const { walletAddress, username } = req.body;

    // Generate authentication options
    const { options, allowedDevices } = await webAuthnService.generateAuthenticationOptions(
      walletAddress,
      username
    );

    logger.webauthn('Authentication options generated', {
      walletAddress,
      username,
      allowedDevicesCount: allowedDevices.length,
    });

    const response: ApiResponse = {
      success: true,
      data: {
        options,
        hasDevices: allowedDevices.length > 0,
        deviceCount: allowedDevices.length,
      },
    };

    res.json(response);
  })
);

/**
 * POST /webauthn/login/verify
 * Verify authentication response
 */
router.post(
  '/login/verify',
  authRateLimit,
  validateRequest(AuthenticationFinishSchema),
  asyncHandler(async (req: Request, res: Response) => {
    const { credential } = req.body;

    // Verify authentication
    const { user, device } = await webAuthnService.verifyAuthenticationResponse(credential);

    // Create session
    const { token, session } = await jwtService.createSession(
      user,
      device,
      req.ip || 'unknown',
      req.get('User-Agent') || 'unknown'
    );

    logger.webauthn('Authentication completed and session created', {
      userId: user.id,
      deviceId: device.id,
      sessionId: session.sessionId,
    });

    const response: ApiResponse = {
      success: true,
      data: {
        user: {
          id: user.id,
          username: user.username,
          walletAddress: user.walletAddress,
          lastLoginAt: user.lastLoginAt,
        },
        device: {
          id: device.id,
          name: device.name,
          lastUsedAt: device.lastUsedAt,
        },
        token,
        expiresAt: session.expiresAt,
      },
    };

    res.json(response);
  })
);

/**
 * GET /webauthn/me
 * Get current user information
 */
router.get(
  '/me',
  authenticate,
  asyncHandler(async (req: Request, res: Response) => {
    const user = req.user;
    const session = req.session;

    // Get user devices
    const devices = await webAuthnService.getUserDevices(user.id);

    logger.auth('User info requested', {
      userId: user.id,
      sessionId: session.sessionId,
    });

    const response: ApiResponse = {
      success: true,
      data: {
        user: {
          id: user.id,
          username: user.username,
          walletAddress: user.walletAddress,
          createdAt: user.createdAt,
          lastLoginAt: user.lastLoginAt,
        },
        session: {
          sessionId: session.sessionId,
          deviceId: session.deviceId,
          issuedAt: session.issuedAt,
          expiresAt: session.expiresAt,
        },
        devices: devices.map(device => ({
          id: device.id,
          name: device.name,
          createdAt: device.createdAt,
          lastUsedAt: device.lastUsedAt,
        })),
      },
    };

    res.json(response);
  })
);

/**
 * POST /webauthn/refresh
 * Refresh session token
 */
router.post(
  '/refresh',
  authenticate,
  asyncHandler(async (req: Request, res: Response) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      throw new WebAuthnError('Authorization header required', 'MISSING_AUTH_HEADER', 401);
    }

    const token = jwtService.extractTokenFromHeader(authHeader);
    if (!token) {
      throw new WebAuthnError('Invalid authorization header format', 'INVALID_AUTH_HEADER', 401);
    }

    // Refresh session
    const { token: newToken, session: newSession } = await jwtService.refreshSession(token);

    logger.auth('Session refreshed', {
      userId: req.user.id,
      oldSessionId: req.session.sessionId,
      newSessionId: newSession.sessionId,
    });

    const response: ApiResponse = {
      success: true,
      data: {
        token: newToken,
        expiresAt: newSession.expiresAt,
      },
    };

    res.json(response);
  })
);

/**
 * POST /webauthn/logout
 * Logout and invalidate session
 */
router.post(
  '/logout',
  authenticate,
  asyncHandler(async (req: Request, res: Response) => {
    const session = req.session;

    // Invalidate session
    await jwtService.invalidateSession(session.sessionId);

    logger.auth('User logged out', {
      userId: req.user.id,
      sessionId: session.sessionId,
    });

    const response: ApiResponse = {
      success: true,
      message: 'Logged out successfully',
    };

    res.json(response);
  })
);

/**
 * DELETE /webauthn/devices/:deviceId
 * Remove a device
 */
router.delete(
  '/devices/:deviceId',
  authenticate,
  asyncHandler(async (req: Request, res: Response) => {
    const { deviceId } = req.params;
    const user = req.user;

    // Remove device
    await webAuthnService.removeDevice(user.id, deviceId);

    logger.webauthn('Device removed', {
      userId: user.id,
      deviceId,
    });

    const response: ApiResponse = {
      success: true,
      message: 'Device removed successfully',
    };

    res.json(response);
  })
);

/**
 * GET /webauthn/devices
 * Get user devices
 */
router.get(
  '/devices',
  authenticate,
  asyncHandler(async (req: Request, res: Response) => {
    const user = req.user;

    const devices = await webAuthnService.getUserDevices(user.id);

    const response: ApiResponse = {
      success: true,
      data: {
        devices: devices.map(device => ({
          id: device.id,
          name: device.name,
          createdAt: device.createdAt,
          lastUsedAt: device.lastUsedAt,
        })),
      },
    };

    res.json(response);
  })
);

/**
 * GET /webauthn/health
 * Health check endpoint
 */
router.get(
  '/health',
  asyncHandler(async (req: Request, res: Response) => {
    const health = await webAuthnService.healthCheck();

    const response: ApiResponse = {
      success: true,
      data: health,
    };

    res.json(response);
  })
);

export default router;
