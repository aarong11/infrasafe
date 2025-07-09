/**
 * Test setup for WebAuthn server
 */

// Set test environment variables FIRST before any imports
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-jwt-secret-key-for-testing-only';
process.env.COOKIE_SECRET = 'test-cookie-secret-for-testing-only';
process.env.ETH_RPC_URL = 'http://localhost:8545';
process.env.WEBAUTHN_PORT = '3002';
process.env.RP_NAME = 'InfraSafe Test';
process.env.RP_ID = 'localhost';
process.env.ORIGIN = 'http://localhost:3002';

import { config } from '../src/utils/config';
import { storageService } from '../src/services/storage';

// Mock console methods in tests to reduce noise
const originalConsole = { ...console };

beforeEach(() => {
  // Quiet console in tests
  console.log = jest.fn();
  console.info = jest.fn();
  console.warn = jest.fn();
  console.error = jest.fn();
  console.debug = jest.fn();
});

afterEach(() => {
  // Restore console
  Object.assign(console, originalConsole);
});

// Clean up storage before each test
beforeEach(async () => {
  await storageService.reset();
});

// Clean up after all tests
afterAll(async () => {
  await storageService.shutdown();
});

// Global test timeout
jest.setTimeout(30000);

// Mock WebAuthn crypto operations for testing
global.crypto = {
  getRandomValues: (arr: any) => {
    for (let i = 0; i < arr.length; i++) {
      arr[i] = Math.floor(Math.random() * 256);
    }
    return arr;
  },
  subtle: {
    digest: jest.fn(),
    sign: jest.fn(),
    verify: jest.fn(),
    generateKey: jest.fn(),
    importKey: jest.fn(),
    exportKey: jest.fn(),
  },
} as any;

// Mock WebAuthn globals for Node.js environment
global.navigator = {
  credentials: {
    create: jest.fn(),
    get: jest.fn(),
  },
} as any;

// Mock fetch for ABI server calls
global.fetch = jest.fn();

export {};
