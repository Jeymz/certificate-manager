module.exports = {
  setupFiles: ['<rootDir>/tests/preSetup.js'],
  setupFilesAfterEnv: ['<rootDir>/tests/testSetup.js'],
  coverageThreshold: {
    global: {
      branches: 75,
      functions: 90,
      lines: 90,
      statements: 90
    }
  }
};
