import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { config, isDevelopment } from './utils/config';
import { logger } from './utils/logger';
import { errorHandler, notFoundHandler } from './middleware/error';
import { generalRateLimit } from './middleware/rateLimit';
import { 
  requestLogger, 
  validateIP, 
  validateUserAgent,
  validateRequestSize 
} from './middleware/security';

// Import routes
import webAuthnRoutes from './routes/webauthn';
import walletRoutes from './routes/wallet';

/**
 * InfraSafe WebAuthn API Server
 * 
 * Provides passwordless authentication using WebAuthn and smart contract integration
 */
class WebAuthnServer {
  private app: express.Application;
  private server: any;

  constructor() {
    this.app = express();
    this.setupMiddleware();
    this.setupRoutes();
    this.setupErrorHandling();
  }

  /**
   * Setup application middleware
   */
  private setupMiddleware(): void {
    // Security middleware
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: ["'self'"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          frameSrc: ["'none'"],
        },
      },
      crossOriginEmbedderPolicy: false,
    }));

    // CORS configuration
    this.app.use(cors({
      origin: (origin, callback) => {
        // Allow requests with no origin (mobile apps, Postman, tests, etc.)
        if (!origin) {
          if (isDevelopment || config.nodeEnv === 'test') {
            return callback(null, true);
          }
          return callback(new Error('Origin required'), false);
        }

        if (config.corsOrigins.includes(origin)) {
          return callback(null, true);
        }

        logger.security('CORS origin rejected', { origin });
        callback(new Error('Origin not allowed by CORS'), false);
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-Requested-With',
        'X-CSRF-Token',
        'User-Agent',
        'Accept',
        'Origin',
      ],
      exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
    }));

    // Trust proxy (for accurate IP addresses behind load balancers)
    if (!isDevelopment) {
      this.app.set('trust proxy', 1);
    }

    // Body parsing
    this.app.use(express.json({ 
      limit: '1mb',
      strict: true,
    }));
    this.app.use(express.urlencoded({ 
      extended: false, 
      limit: '1mb',
    }));

    // Cookie parsing
    this.app.use(cookieParser(config.cookieSecret));

    // Security middleware
    this.app.use(validateIP);
    this.app.use(validateUserAgent);
    this.app.use(validateRequestSize(1024 * 1024)); // 1MB limit

    // Request logging
    this.app.use(requestLogger);

    // Rate limiting
    this.app.use(generalRateLimit);
  }

  /**
   * Setup application routes
   */
  private setupRoutes(): void {
    // Health check endpoint (no authentication required)
    this.app.get('/health', (req, res) => {
      res.json({
        success: true,
        data: {
          status: 'healthy',
          timestamp: new Date().toISOString(),
          version: '1.0.0',
          environment: config.nodeEnv,
        },
      });
    });

    // API version endpoint
    this.app.get('/version', (req, res) => {
      res.json({
        success: true,
        data: {
          version: '1.0.0',
          apiVersion: 'v1',
          nodeVersion: process.version,
          environment: config.nodeEnv,
        },
      });
    });

    // Mount route handlers
    this.app.use('/webauthn', webAuthnRoutes);
    this.app.use('/wallet', walletRoutes);

    // Root endpoint - serve API documentation
    this.app.get('/', (req, res) => {
      res.json({
        success: true,
        data: {
          title: 'InfraSafe WebAuthn API',
          description: 'Passwordless authentication API for InfraSafe multisig wallets',
          version: '1.0.0',
          links: {
            documentation: '/docs',
            health: '/health'
          }
        }
      });
    });

    // API documentation endpoint
    this.app.get('/docs', (req, res) => {
      res.json({
        success: true,
        data: {
          title: 'InfraSafe WebAuthn API',
          description: 'Passwordless authentication API for InfraSafe multisig wallets',
          version: '1.0.0',
          endpoints: {
            authentication: {
              'POST /webauthn/register/options': 'Generate WebAuthn registration options',
              'POST /webauthn/register/verify': 'Verify WebAuthn registration',
              'POST /webauthn/login/options': 'Generate WebAuthn authentication options',
              'POST /webauthn/login/verify': 'Verify WebAuthn authentication',
              'GET /webauthn/me': 'Get current user information',
              'POST /webauthn/refresh': 'Refresh authentication token',
              'POST /webauthn/logout': 'Logout and invalidate session',
              'GET /webauthn/devices': 'Get user devices',
              'DELETE /webauthn/devices/:deviceId': 'Remove a device',
            },
            wallet: {
              'GET /wallet/:address/status': 'Get wallet status and permissions',
              'POST /wallet/:address/submit': 'Submit multisig transaction',
              'POST /wallet/:address/simulate': 'Simulate transaction execution',
              'GET /wallet/:address/transactions': 'Get transaction history',
              'GET /wallet/:address/signers': 'Get wallet signers',
              'GET /wallet/:address/nonce': 'Get current wallet nonce',
              'POST /wallet/:address/transaction-hash': 'Generate transaction hash for signing',
              'GET /wallet/:address/balance': 'Get wallet ETH balance',
            },
          },
          authentication: {
            type: 'Bearer JWT',
            header: 'Authorization: Bearer <token>',
            description: 'Include JWT token received from WebAuthn authentication',
          },
        },
      });
    });
  }

  /**
   * Setup error handling
   */
  private setupErrorHandling(): void {
    // 404 handler
    this.app.use('*', notFoundHandler);

    // Global error handler
    this.app.use(errorHandler);
  }

  /**
   * Start the server
   */
  public start(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        this.server = this.app.listen(config.port, () => {
          logger.info('🌐 InfraSafe WebAuthn API Server');
          logger.info('═══════════════════════════════════');
          logger.info(`🚀 Server running on http://localhost:${config.port}`);
          logger.info(`📋 Environment: ${config.nodeEnv}`);
          logger.info(`🔐 CORS Origins: ${config.corsOrigins.join(', ')}`);
          logger.info(`⏱️  Challenge Timeout: ${config.challengeTimeout}ms`);
          logger.info(`🔑 JWT Expires In: ${config.jwtExpiresIn}`);
          logger.info('');
          logger.info('📋 Available endpoints:');
          logger.info(`   • GET  http://localhost:${config.port}/health`);
          logger.info(`   • GET  http://localhost:${config.port}/docs`);
          logger.info(`   • POST http://localhost:${config.port}/webauthn/register/options`);
          logger.info(`   • POST http://localhost:${config.port}/webauthn/login/options`);
          logger.info(`   • GET  http://localhost:${config.port}/wallet/:address/status`);
          logger.info('');
          logger.info('🔗 Related services:');
          logger.info(`   • ABI Server: ${config.abiServerUrl}:${config.abiServerPort}`);
          logger.info(`   • Ethereum RPC: ${config.ethRpcUrl}`);
          logger.info('');

          resolve();
        });

        this.server.on('error', (error: any) => {
          if (error.code === 'EADDRINUSE') {
            logger.error(`Port ${config.port} is already in use`);
          } else {
            logger.error('Server error:', error);
          }
          reject(error);
        });

        // Graceful shutdown
        this.setupGracefulShutdown();

      } catch (error) {
        logger.error('Failed to start server:', error);
        reject(error);
      }
    });
  }

  /**
   * Setup graceful shutdown handlers
   */
  private setupGracefulShutdown(): void {
    const shutdown = (signal: string) => {
      logger.info(`\n🛑 Received ${signal}, shutting down gracefully...`);
      
      if (this.server) {
        this.server.close(() => {
          logger.info('✅ Server closed');
          process.exit(0);
        });

        // Force shutdown after 10 seconds
        setTimeout(() => {
          logger.warn('⚠️  Forced shutdown');
          process.exit(1);
        }, 10000);
      } else {
        process.exit(0);
      }
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));

    process.on('unhandledRejection', (reason, promise) => {
      logger.error('Unhandled Rejection', { reason, promise });
    });

    process.on('uncaughtException', (error) => {
      logger.error('Uncaught Exception:', error);
      process.exit(1);
    });
  }

  /**
   * Stop the server
   */
  public stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          logger.info('Server stopped');
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  /**
   * Get the Express app instance
   */
  public getApp(): express.Application {
    return this.app;
  }
}

// Create and export server instance
const webAuthnServer = new WebAuthnServer();

// Start server if this file is run directly
if (require.main === module) {
  webAuthnServer.start().catch((error) => {
    logger.error('Failed to start server:', error);
    process.exit(1);
  });
}

export default webAuthnServer;
export { WebAuthnServer };
