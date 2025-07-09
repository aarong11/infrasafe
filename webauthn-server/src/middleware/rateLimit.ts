import { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import { config } from '../utils/config';
import { logger } from '../utils/logger';

/**
 * Rate limiting configurations
 */

// General API rate limit
export const generalRateLimit = rateLimit({
  windowMs: config.rateLimitWindow,
  max: config.rateLimitMax,
  message: {
    success: false,
    error: 'Too many requests, please try again later',
    code: 'RATE_LIMIT_EXCEEDED'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request) => {
    // Use user ID if authenticated, otherwise IP
    return req.user?.id || req.ip || 'unknown';
  },
  handler: (req: Request, res: Response) => {
    logger.security('Rate limit exceeded', {
      ip: req.ip,
      userId: req.user?.id,
      path: req.path,
      method: req.method,
      userAgent: req.get('User-Agent'),
    });
    
    res.status(429).json({
      success: false,
      error: 'Too many requests, please try again later',
      code: 'RATE_LIMIT_EXCEEDED'
    });
  },
});

// Strict rate limit for authentication endpoints
export const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per window
  message: {
    success: false,
    error: 'Too many authentication attempts, please try again later',
    code: 'AUTH_RATE_LIMIT_EXCEEDED'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request) => {
    // Use wallet address or username if provided, otherwise IP
    const walletAddress = req.body?.walletAddress;
    const username = req.body?.username;
    return walletAddress || username || req.ip || 'unknown';
  },
  handler: (req: Request, res: Response) => {
    logger.security('Authentication rate limit exceeded', {
      ip: req.ip,
      walletAddress: req.body?.walletAddress,
      username: req.body?.username,
      path: req.path,
      method: req.method,
      userAgent: req.get('User-Agent'),
    });
    
    res.status(429).json({
      success: false,
      error: 'Too many authentication attempts, please try again later',
      code: 'AUTH_RATE_LIMIT_EXCEEDED'
    });
  },
});

// Registration rate limit
export const registrationRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 registrations per hour per IP
  message: {
    success: false,
    error: 'Too many registration attempts, please try again later',
    code: 'REGISTRATION_RATE_LIMIT_EXCEEDED'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request) => req.ip || 'unknown',
  handler: (req: Request, res: Response) => {
    logger.security('Registration rate limit exceeded', {
      ip: req.ip,
      path: req.path,
      method: req.method,
      userAgent: req.get('User-Agent'),
    });
    
    res.status(429).json({
      success: false,
      error: 'Too many registration attempts, please try again later',
      code: 'REGISTRATION_RATE_LIMIT_EXCEEDED'
    });
  },
});

// Transaction rate limit
export const transactionRateLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 transactions per minute per user
  message: {
    success: false,
    error: 'Too many transaction attempts, please slow down',
    code: 'TRANSACTION_RATE_LIMIT_EXCEEDED'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request) => {
    return req.user?.id || req.ip || 'unknown';
  },
  handler: (req: Request, res: Response) => {
    logger.security('Transaction rate limit exceeded', {
      ip: req.ip,
      userId: req.user?.id,
      walletAddress: req.params?.address,
      path: req.path,
      method: req.method,
    });
    
    res.status(429).json({
      success: false,
      error: 'Too many transaction attempts, please slow down',
      code: 'TRANSACTION_RATE_LIMIT_EXCEEDED'
    });
  },
});

/**
 * Custom rate limiting middleware for specific scenarios
 */
export const createCustomRateLimit = (
  windowMs: number,
  max: number,
  message: string,
  keyGenerator?: (req: Request) => string
) => {
  return rateLimit({
    windowMs,
    max,
    message: {
      success: false,
      error: message,
      code: 'CUSTOM_RATE_LIMIT_EXCEEDED'
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: keyGenerator || ((req: Request) => req.ip || 'unknown'),
    handler: (req: Request, res: Response) => {
      logger.security('Custom rate limit exceeded', {
        ip: req.ip,
        userId: req.user?.id,
        path: req.path,
        method: req.method,
        windowMs,
        max,
      });
      
      res.status(429).json({
        success: false,
        error: message,
        code: 'CUSTOM_RATE_LIMIT_EXCEEDED'
      });
    },
  });
};
