import { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';
import { WebAuthnError, ContractError, AuthenticationError } from '../types';
import { logger } from '../utils/logger';

/**
 * Error handling middleware
 */
export const errorHandler = (
  error: any,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  // Log error
  logger.error('Request error', {
    error: error.message,
    stack: error.stack,
    path: req.path,
    method: req.method,
    userId: req.user?.id,
    ip: req.ip,
  });

  // Handle different error types
  if (error instanceof WebAuthnError) {
    res.status(error.statusCode).json({
      success: false,
      error: error.message,
      code: error.code,
    });
    return;
  }

  if (error instanceof ContractError) {
    res.status(error.statusCode).json({
      success: false,
      error: error.message,
      code: error.code,
      contractAddress: error.contractAddress,
    });
    return;
  }

  if (error instanceof AuthenticationError) {
    res.status(error.statusCode).json({
      success: false,
      error: error.message,
      code: error.code,
    });
    return;
  }

  if (error instanceof ZodError) {
    res.status(400).json({
      success: false,
      error: 'Validation error',
      code: 'VALIDATION_ERROR',
      details: error.errors.map(err => ({
        field: err.path.join('.'),
        message: err.message,
      })),
    });
    return;
  }

  // Handle specific error types
  if (error.name === 'ValidationError') {
    res.status(400).json({
      success: false,
      error: 'Validation error',
      code: 'VALIDATION_ERROR',
      details: error.message,
    });
    return;
  }

  if (error.name === 'CastError') {
    res.status(400).json({
      success: false,
      error: 'Invalid data format',
      code: 'INVALID_DATA_FORMAT',
    });
    return;
  }

  if (error.code === 'ECONNREFUSED') {
    res.status(503).json({
      success: false,
      error: 'Service unavailable',
      code: 'SERVICE_UNAVAILABLE',
    });
    return;
  }

  // Default error response
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    code: 'INTERNAL_ERROR',
  });
};

/**
 * 404 handler
 */
export const notFoundHandler = (req: Request, res: Response): void => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    code: 'NOT_FOUND',
    path: req.path,
    method: req.method,
  });
};

/**
 * Request validation middleware
 */
export const validateRequest = (schema: any, property: 'body' | 'params' | 'query' = 'body') => {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      const data = req[property];
      const validated = schema.parse(data);
      req[property] = validated;
      next();
    } catch (error) {
      next(error);
    }
  };
};

/**
 * Async error wrapper
 */
export const asyncHandler = (fn: Function) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};
