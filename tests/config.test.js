const configFactory = require('../src/resources/config');

describe('config resource', () => {
  test('getServerConfig returns server config', () => {
    const config = configFactory();
    expect(config.getServerConfig()).toEqual({ port: 3000 });
  });

  test('isInitialized returns false without files', () => {
    const config = configFactory();
    expect(config.isInitialized()).toBe(false);
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
});
