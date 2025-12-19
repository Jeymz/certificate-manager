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
    const extensions = config.getCertExtensions();
    expect(extensions).toHaveProperty('webServer');
    expect(extensions).toHaveProperty('ldapServer');
  });

  test('getDefaultIntermediate returns configured value', () => {
    const config = configFactory();
    expect(config.getDefaultIntermediate()).toBe('intermediateCA.example.com');
  });

  test('getRequireIntermediate returns configured value', () => {
    const config = configFactory();
    expect(config.getRequireIntermediate()).toBe(true);
  });

  test('getValidityLimits returns defaults and configured limits', () => {
    const config = configFactory();
    const limits = config.getValidityLimits();
    expect(limits).toHaveProperty('minDays');
    expect(limits).toHaveProperty('maxDays');
  });

  test('getProfileValidity returns configured profile metadata or null', () => {
    const fs = require('fs');
    // Load the defaults.json and modify a copy to include profileMetadata
    const defaultsPath = require('path').join(__dirname, '..', 'config', 'defaults.json');
    const original = fs.readFileSync(defaultsPath, 'utf8');
    const parsed = JSON.parse(original);
    parsed.profileMetadata = { webServer: { validityDays: 90 } };
    jest.spyOn(fs, 'readFileSync').mockReturnValueOnce(JSON.stringify(parsed));
    jest.resetModules();
    const freshFactory = require('../src/resources/config');
    const fresh = freshFactory();
    expect(fresh.getProfileValidity('webServer')).toBe(90);
    fs.readFileSync.mockRestore();
  });
});
