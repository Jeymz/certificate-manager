module.exports = {
  setupFiles: ['<rootDir>/tests/preSetup.js'],
  globalTeardown: '<rootDir>/tests/globalTeardown.js',
  coverageThreshold: {
    global: {
      branches: 75,
      functions: 90,
      lines: 90,
      statements: 90
    }
  }
};
