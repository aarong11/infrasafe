import { Request, Response, NextFunction } from 'express';
import { AuthenticationError } from '../types';
import { jwtService } from '../services/jwt';
import { logger } from '../utils/logger';

// Extend Express Request interface
declare global {
  namespace Express {
    interface Request {
      user?: any;
      session?: any;
      payload?: any;
    }
  }
}

/**
 * Authentication middleware
 */
export const authenticate = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      res.status(401).json({
        success: false,
        error: 'Authorization header required',
        code: 'MISSING_AUTH_HEADER'
      });
      return;
    }

    const token = jwtService.extractTokenFromHeader(authHeader);
    if (!token) {
      res.status(401).json({
        success: false,
        error: 'Invalid authorization header format',
        code: 'INVALID_AUTH_HEADER'
      });
      return;
    }

    const { user, session, payload } = await jwtService.validateSession(token);

    // Attach to request
    req.user = user;
    req.session = session;
    req.payload = payload;

    logger.debug('Request authenticated', {
      userId: user.id,
      sessionId: session.sessionId,
      path: req.path,
      method: req.method,
    });

    next();
  } catch (error) {
    if (error instanceof AuthenticationError) {
      res.status(error.statusCode).json({
        success: false,
        error: error.message,
        code: error.code
      });
      return;
    }

    logger.error('Authentication middleware error', {
      error: error instanceof Error ? error.message : error,
      path: req.path,
      method: req.method,
    });

    res.status(500).json({
      success: false,
      error: 'Internal server error',
      code: 'INTERNAL_ERROR'
    });
  }
};

/**
 * Optional authentication middleware (doesn't fail if no token)
 */
export const optionalAuthenticate = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      next();
      return;
    }

    const token = jwtService.extractTokenFromHeader(authHeader);
    if (!token) {
      next();
      return;
    }

    const { user, session, payload } = await jwtService.validateSession(token);

    // Attach to request
    req.user = user;
    req.session = session;
    req.payload = payload;

    next();
  } catch (error) {
    // Log error but don't fail the request
    logger.debug('Optional authentication failed', {
      error: error instanceof Error ? error.message : error,
      path: req.path,
      method: req.method,
    });
    next();
  }
};

/**
 * Require wallet ownership middleware
 */
export const requireWalletOwnership = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  if (!req.user) {
    res.status(401).json({
      success: false,
      error: 'Authentication required',
      code: 'AUTHENTICATION_REQUIRED'
    });
    return;
  }

  const walletAddress = req.params.address?.toLowerCase();
  const userWalletAddress = req.user.walletAddress?.toLowerCase();

  if (!walletAddress || !userWalletAddress) {
    res.status(400).json({
      success: false,
      error: 'Wallet address required',
      code: 'WALLET_ADDRESS_REQUIRED'
    });
    return;
  }

  if (walletAddress !== userWalletAddress) {
    logger.security('Wallet ownership mismatch', {
      userId: req.user.id,
      requestedWallet: walletAddress,
      userWallet: userWalletAddress,
      path: req.path,
      method: req.method,
    });

    res.status(403).json({
      success: false,
      error: 'Access denied: wallet ownership required',
      code: 'WALLET_OWNERSHIP_REQUIRED'
    });
    return;
  }

  next();
};
