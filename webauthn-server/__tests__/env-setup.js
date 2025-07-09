// Environment setup for Jest tests
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-jwt-secret-key-for-testing-only';
process.env.COOKIE_SECRET = 'test-cookie-secret-for-testing-only';
process.env.ETH_RPC_URL = 'http://localhost:8545';
process.env.WEBAUTHN_PORT = '3002';
process.env.RP_NAME = 'InfraSafe Test';
process.env.RP_ID = 'localhost';
process.env.ORIGIN = 'http://localhost:3002';
process.env.CORS_ORIGINS = 'http://localhost:3000,http://localhost:3001,http://localhost:3002';
process.env.CHALLENGE_TIMEOUT = '300000';
process.env.SESSION_TIMEOUT = '86400000';
process.env.JWT_EXPIRES_IN = '24h';
process.env.ETH_CHAIN_ID = '31337';
process.env.RATE_LIMIT_WINDOW = '900000';
process.env.RATE_LIMIT_MAX = '100';
process.env.CACHE_DEFAULT_TTL = '300';
process.env.CACHE_CHECK_PERIOD = '60';
