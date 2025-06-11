module.exports = {
  setupFiles: ['<rootDir>/tests/preSetup.js'],
  globalTeardown: '<rootDir>/tests/globalTeardown.js',
  coveragePathIgnorePatterns: [
    '<rootDir>/src/utils/logger.js',
    '<rootDir>/scripts/',
    '<rootDir>/src/resources/revocation.js',
    '<rootDir>/src/routers/certRouter.js',
  ],
  coverageThreshold: {
    global: {
      branches: 75,
      functions: 90,
      lines: 90,
      statements: 90,
    },
  },
};
