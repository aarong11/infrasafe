import * as dotenv from 'dotenv';

dotenv.config();

export interface Config {
  // Server configuration
  port: number;
  nodeEnv: string;
  corsOrigins: string[];
  
  // WebAuthn configuration
  rpName: string;
  rpId: string;
  origin: string;
  challengeTimeout: number;
  sessionTimeout: number;
  
  // JWT configuration
  jwtSecret: string;
  jwtExpiresIn: string;
  
  // Ethereum configuration
  ethRpcUrl: string;
  ethPrivateKey?: string;
  ethChainId: number;
  
  // ABI Server configuration
  abiServerUrl: string;
  abiServerPort: number;
  
  // Rate limiting
  rateLimitWindow: number;
  rateLimitMax: number;
  
  // Security
  cookieSecret: string;
  bcryptRounds: number;
  
  // Cache
  cacheMaxAge: number;
  cachCheckPeriod: number;
}

const getConfig = (): Config => {
  const requiredEnvVars = [
    'JWT_SECRET',
    'COOKIE_SECRET',
    'ETH_RPC_URL'
  ];

  for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
      throw new Error(`Missing required environment variable: ${envVar}`);
    }
  }

  return {
    // Server
    port: parseInt(process.env.WEBAUTHN_PORT || '3001', 10),
    nodeEnv: process.env.NODE_ENV || 'development',
    corsOrigins: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000', 'http://localhost:3001'],
    
    // WebAuthn
    rpName: process.env.RP_NAME || 'InfraSafe',
    rpId: process.env.RP_ID || 'localhost',
    origin: process.env.ORIGIN || 'http://localhost:3001',
    challengeTimeout: parseInt(process.env.CHALLENGE_TIMEOUT || '300000', 10), // 5 minutes
    sessionTimeout: parseInt(process.env.SESSION_TIMEOUT || '86400000', 10), // 24 hours
    
    // JWT
    jwtSecret: process.env.JWT_SECRET!,
    jwtExpiresIn: process.env.JWT_EXPIRES_IN || '24h',
    
    // Ethereum
    ethRpcUrl: process.env.ETH_RPC_URL!,
    ethPrivateKey: process.env.ETH_PRIVATE_KEY,
    ethChainId: parseInt(process.env.ETH_CHAIN_ID || '31337', 10),
    
    // ABI Server
    abiServerUrl: process.env.ABI_SERVER_URL || 'http://localhost',
    abiServerPort: parseInt(process.env.ABI_SERVER_PORT || '5656', 10),
    
    // Rate limiting
    rateLimitWindow: parseInt(process.env.RATE_LIMIT_WINDOW || '900000', 10), // 15 minutes
    rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX || '100', 10),
    
    // Security
    cookieSecret: process.env.COOKIE_SECRET!,
    bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS || '12', 10),
    
    // Cache
    cacheMaxAge: parseInt(process.env.CACHE_MAX_AGE || '600', 10), // 10 minutes
    cachCheckPeriod: parseInt(process.env.CACHE_CHECK_PERIOD || '120', 10), // 2 minutes
  };
};

export const config = getConfig();

export const isProduction = config.nodeEnv === 'production';
export const isDevelopment = config.nodeEnv === 'development';
export const isTest = config.nodeEnv === 'test';
