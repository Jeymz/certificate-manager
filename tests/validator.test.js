const fs = require('fs');
const path = require('path');
const Validator = require('../src/resources/validator');

const config = JSON.parse(fs.readFileSync(path.join(__dirname, '../config/defaults.example.json')));

describe('validator', () => {
  const validator = new Validator(config);

  test('valid hostname is accepted', () => {
    expect(validator.hostname('foo.example.com')).toBe(true);
  });

  test('invalid hostname is rejected', () => {
    expect(validator.hostname('foo.com')).toBe(false);
    expect(validator.hostname('badhost')).toBe(false);
    expect(validator.hostname('foo.bad.com')).toBe(false);
  });

  test('schema validation', () => {
    const valid = {
      hostname: 'foo.example.com',
      passphrase: 'secret'
    };
    expect(validator.validateSchema('new', valid)).toBe(true);
    expect(validator.validateSchema('new', { hostname: 'x' })).toBe(false);
  });
});
