module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/webauthn-server'],
  testMatch: [
    '<rootDir>/webauthn-server/**/__tests__/**/integration.test.ts'
  ],
  transform: {
    '^.+\\.ts$': 'ts-jest'
  },
  setupFiles: ['<rootDir>/webauthn-server/__tests__/env-setup.js'],
  // Don't use the setup file that mocks console
  // setupFilesAfterEnv: ['<rootDir>/webauthn-server/__tests__/setup.ts'],
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/webauthn-server/src/$1'
  },
  testTimeout: 30000
};
