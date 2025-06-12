const configFactory = require('../src/resources/config');

describe('config resource', () => {
  test('getServerConfig returns server config', () => {
    const config = configFactory();
    expect(config.getServerConfig()).toEqual({
      port: 3000,
      protocol: 'https',
      key: './ssl/server.key',
      cert: './ssl/server.crt',
    });
  });

  test('isInitialized returns false without files', () => {
    const fs = require('fs');
    jest.spyOn(fs, 'existsSync').mockReturnValue(false);
    jest.resetModules();
    const freshFactory = require('../src/resources/config');
    const config = freshFactory();
    expect(config.isInitialized()).toBe(false);
    fs.existsSync.mockRestore();
  });

  test('isInitialized true when files present', () => {
    const fs = require('fs');
    jest.spyOn(fs, 'existsSync').mockReturnValue(true);
    jest.resetModules();
    const freshFactory = require('../src/resources/config');
    const fresh = freshFactory();
    expect(fresh.isInitialized()).toBe(true);
    fs.existsSync.mockRestore();
  });

  test('getSubject returns subject defaults', () => {
    const config = configFactory();
    const subject = config.getSubject();
    expect(Array.isArray(subject)).toBe(true);
    expect(subject.find(s => s.shortName === 'C').value).toBe('US');
  });

  test('getValidator provides working validator', () => {
    const config = configFactory();
    const validator = config.getValidator();
    expect(validator.hostname('test.example.com')).toBe(true);
  });

  test('getStoreDirectory and extensions', () => {
    const config = configFactory();
    expect(config.getStoreDirectory()).toContain('files_test');
    expect(config.getCertExtensions()).toHaveProperty('webServer');
  });

  test('getDefaultIntermediate returns configured value', () => {
    const config = configFactory();
    expect(config.getDefaultIntermediate()).toBe('intermediate');
  });
});
