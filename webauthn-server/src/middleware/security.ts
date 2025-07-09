import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
import { config, isDevelopment } from '../utils/config';

/**
 * Security middleware
 */

/**
 * CORS validation middleware
 */
export const validateOrigin = (req: Request, res: Response, next: NextFunction): void => {
  const origin = req.get('Origin');
  
  if (!origin) {
    if (isDevelopment) {
      next();
      return;
    }
    
    logger.security('Request without origin header', {
      ip: req.ip,
      path: req.path,
      method: req.method,
      userAgent: req.get('User-Agent'),
    });
    
    res.status(400).json({
      success: false,
      error: 'Origin header required',
      code: 'MISSING_ORIGIN'
    });
    return;
  }

  if (!config.corsOrigins.includes(origin)) {
    logger.security('Invalid origin', {
      origin,
      ip: req.ip,
      path: req.path,
      method: req.method,
    });
    
    res.status(403).json({
      success: false,
      error: 'Origin not allowed',
      code: 'INVALID_ORIGIN'
    });
    return;
  }

  next();
};

/**
 * WebAuthn origin validation
 */
export const validateWebAuthnOrigin = (req: Request, res: Response, next: NextFunction): void => {
  const origin = req.get('Origin');
  
  if (!origin) {
    res.status(400).json({
      success: false,
      error: 'Origin header required for WebAuthn',
      code: 'MISSING_ORIGIN'
    });
    return;
  }

  if (origin !== config.origin) {
    logger.security('WebAuthn origin mismatch', {
      expected: config.origin,
      received: origin,
      ip: req.ip,
      path: req.path,
    });
    
    res.status(403).json({
      success: false,
      error: 'Invalid origin for WebAuthn',
      code: 'WEBAUTHN_ORIGIN_MISMATCH'
    });
    return;
  }

  next();
};

/**
 * Content-Type validation
 */
export const validateContentType = (expectedType: string = 'application/json') => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (req.method === 'GET' || req.method === 'DELETE') {
      next();
      return;
    }

    const contentType = req.get('Content-Type');
    
    if (!contentType || !contentType.includes(expectedType)) {
      res.status(400).json({
        success: false,
        error: `Content-Type must be ${expectedType}`,
        code: 'INVALID_CONTENT_TYPE'
      });
      return;
    }

    next();
  };
};

/**
 * User-Agent validation
 */
export const validateUserAgent = (req: Request, res: Response, next: NextFunction): void => {
  const userAgent = req.get('User-Agent');
  
  if (!userAgent) {
    logger.security('Request without User-Agent', {
      ip: req.ip,
      path: req.path,
      method: req.method,
    });
    
    if (!isDevelopment && config.nodeEnv !== 'test') {
      res.status(400).json({
        success: false,
        error: 'User-Agent header required',
        code: 'MISSING_USER_AGENT'
      });
      return;
    }
  }

  // Check for suspicious user agents
  const suspiciousPatterns = [
    /bot|crawler|spider|scraper/i,
    /curl|wget|python|java/i,
  ];

  if (userAgent && suspiciousPatterns.some(pattern => pattern.test(userAgent))) {
    logger.security('Suspicious User-Agent detected', {
      userAgent,
      ip: req.ip,
      path: req.path,
      method: req.method,
    });
    
    if (!isDevelopment && config.nodeEnv !== 'test') {
      res.status(403).json({
        success: false,
        error: 'Access denied',
        code: 'SUSPICIOUS_USER_AGENT'
      });
      return;
    }
  }

  next();
};

/**
 * Request size validation
 */
export const validateRequestSize = (maxSize: number = 1024 * 1024) => { // 1MB default
  return (req: Request, res: Response, next: NextFunction): void => {
    const contentLength = req.get('Content-Length');
    
    if (contentLength && parseInt(contentLength) > maxSize) {
      logger.security('Request too large', {
        contentLength: parseInt(contentLength),
        maxSize,
        ip: req.ip,
        path: req.path,
      });
      
      res.status(413).json({
        success: false,
        error: 'Request entity too large',
        code: 'REQUEST_TOO_LARGE'
      });
      return;
    }

    next();
  };
};

/**
 * IP validation (block known bad IPs)
 */
export const validateIP = (req: Request, res: Response, next: NextFunction): void => {
  const ip = req.ip;
  
  if (!ip) {
    logger.security('Request without IP', {
      path: req.path,
      method: req.method,
    });
    next();
    return;
  }
  
  // In production, you would check against a blacklist database
  const blockedIPs: Set<string> = new Set([
    // Add known malicious IPs here
  ]);

  if (blockedIPs.has(ip)) {
    logger.security('Blocked IP attempted access', {
      ip,
      path: req.path,
      method: req.method,
      userAgent: req.get('User-Agent'),
    });
    
    res.status(403).json({
      success: false,
      error: 'Access denied',
      code: 'IP_BLOCKED'
    });
    return;
  }

  next();
};

/**
 * Request logging middleware
 */
export const requestLogger = (req: Request, res: Response, next: NextFunction): void => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    const logData = {
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      userId: req.user?.id,
      contentLength: res.get('Content-Length'),
    };

    if (res.statusCode >= 400) {
      logger.warn('Request failed', logData);
    } else {
      logger.info('Request completed', logData);
    }
  });

  next();
};

/**
 * CSRF token validation (for state-changing operations)
 */
export const validateCSRF = (req: Request, res: Response, next: NextFunction): void => {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
    next();
    return;
  }

  const csrfToken = req.get('X-CSRF-Token') || req.body.csrfToken;
  const sessionToken = req.get('Authorization');

  if (!csrfToken || !sessionToken) {
    res.status(403).json({
      success: false,
      error: 'CSRF token required',
      code: 'CSRF_TOKEN_REQUIRED'
    });
    return;
  }

  // In a real implementation, validate CSRF token against session
  // For now, we'll just check it exists
  if (csrfToken.length < 32) {
    res.status(403).json({
      success: false,
      error: 'Invalid CSRF token',
      code: 'INVALID_CSRF_TOKEN'
    });
    return;
  }

  next();
};
