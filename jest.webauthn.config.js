module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/webauthn-server'],
  testMatch: [
    '<rootDir>/webauthn-server/**/__tests__/**/*.test.ts',
    '<rootDir>/webauthn-server/**/*.test.ts'
  ],
  transform: {
    '^.+\\.ts$': 'ts-jest'
  },
  collectCoverageFrom: [
    'webauthn-server/src/**/*.ts',
    '!webauthn-server/src/**/*.d.ts',
    '!webauthn-server/src/**/*.test.ts',
    '!webauthn-server/src/**/__tests__/**'
  ],
  coverageDirectory: 'coverage/webauthn',
  coverageReporters: ['text', 'lcov', 'html'],
  setupFiles: ['<rootDir>/webauthn-server/__tests__/env-setup.js'],
  setupFilesAfterEnv: ['<rootDir>/webauthn-server/__tests__/setup.ts'],
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/webauthn-server/src/$1'
  },
  testTimeout: 30000
};
