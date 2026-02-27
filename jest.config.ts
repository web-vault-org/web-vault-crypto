export default {
  transform: {
    '^.+\\.ts?$': ['ts-jest', { useESM: true }]
  },
  clearMocks: true,
  testMatch: ['**/tests/**/*.spec.ts'],
  moduleNameMapper: {
    '@/crypto': '<rootDir>/tests/cryptoTest',
    '@/symmetric/argon2': '<rootDir>/tests/symmetric/argon2Test',
    '@/(.*)': '<rootDir>/lib/$1',
    '#/(.*)': '<rootDir>/tests/$1'
  },
  modulePathIgnorePatterns: ['<rootDir>/built', '<rootDir>/frontend'],
  preset: 'ts-jest/presets/default-esm', // ESM Preset
  extensionsToTreatAsEsm: ['.ts']
  /*globals: {
    'ts-jest': {
      useESM: true
    }
  }*/
};
