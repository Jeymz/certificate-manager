module.exports = {
  setupFiles: ['<rootDir>/tests/preSetup.js'],
  globalTeardown: '<rootDir>/tests/globalTeardown.js',
  coveragePathIgnorePatterns: [
    '<rootDir>/src/utils/logger.js',
    '<rootDir>/scripts/',
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
