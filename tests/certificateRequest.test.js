jest.mock('node-forge', () => {
  const mockCsr = {
    setSubject: jest.fn(),
    setAttributes: jest.fn(),
    sign: jest.fn(),
    verify: jest.fn(() => true),
  };
  return {
    pki: {
      rsa: { generateKeyPair: jest.fn(() => ({ publicKey: 'pub', privateKey: 'priv' })) },
      publicKeyToPem: jest.fn(() => 'pubPem'),
      createCertificationRequest: jest.fn(() => mockCsr),
      publicKeyFromPem: jest.fn(),
      certificationRequestToPem: jest.fn(() => 'csrPem'),
      privateKeyToPem: jest.fn(() => 'privPem'),
    },
    asn1: { Type: { UTF8: 'utf8' } },
    __mockCsr: mockCsr,
  };
});

const Request = require('../src/resources/certificateRequest');

describe('certificateRequest', () => {
  test('hostname stored lowercase', () => {
    const req = new Request('Foo.EXAMPLE.com');
    expect(req.getHostname()).toBe('foo.example.com');
  });

  test('constructor rejects invalid hostname', () => {
    expect(() => new Request('badhost')).toThrow('Invalid hostname');
  });

  test('sign generates csr', () => {
    const req = new Request('foo.example.com');
    req.sign();
    expect(req.getCSR()).toBe('csrPem');
  });

  test('verify proxies to csr', () => {
    const req = new Request('foo.example.com');
    req.sign();
    expect(req.verify()).toBe(true);
    expect(require('node-forge').__mockCsr.verify).toHaveBeenCalled();
  });

  test('setCertType validates input', () => {
    const req = new Request('foo.example.com');
    expect(() => req.setCertType('invalid')).toThrow();
    req.setCertType('webServer');
    expect(req.getCertType()).toBe('webServer');
  });

  test('addAltNames adds SAN extension', () => {
    const req = new Request('foo.example.com');
    req.addAltNames(['bar.example.com']);
    req.sign();
    expect(require('node-forge').__mockCsr.setAttributes).toHaveBeenCalled();
  });

  test('invalid SAN entries are ignored', () => {
    const forge = require('node-forge');
    forge.__mockCsr.setAttributes.mockClear();
    const req = new Request('foo.example.com');
    req.addAltNames(['bar.bad.com', 'BAR.EXAMPLE.COM', 'foo.com']);
    req.sign();
    const attrs = forge.__mockCsr.setAttributes.mock.calls[0][0];
    const ext = attrs.find((a) => a.name === 'extensionRequest');
    expect(ext.extensions[0].altNames).toEqual([
      { type: 2, value: 'bar.example.com' },
    ]);
  });

  test('ip SAN entries are allowed', () => {
    const forge = require('node-forge');
    forge.__mockCsr.setAttributes.mockClear();
    const req = new Request('foo.example.com');
    req.addAltNames(['192.168.0.1', 'BAR.EXAMPLE.COM', '10.0.0.1']);
    req.sign();
    const attrs = forge.__mockCsr.setAttributes.mock.calls[0][0];
    const ext = attrs.find((a) => a.name === 'extensionRequest');
    expect(ext.extensions[0].altNames).toEqual([
      { type: 7, ip: '192.168.0.1' },
      { type: 2, value: 'bar.example.com' },
      { type: 7, ip: '10.0.0.1' },
    ]);
  });
});
