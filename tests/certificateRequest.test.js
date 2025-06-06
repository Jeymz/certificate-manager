jest.mock('node-forge', () => {
  const mockCsr = {
    setSubject: jest.fn(),
    setAttributes: jest.fn(),
    sign: jest.fn(),
    verify: jest.fn(() => true)
  };
  return {
    pki: {
      rsa: { generateKeyPair: jest.fn(() => ({ publicKey: 'pub', privateKey: 'priv' })) },
      publicKeyToPem: jest.fn(() => 'pubPem'),
      createCertificationRequest: jest.fn(() => mockCsr),
      publicKeyFromPem: jest.fn(),
      certificationRequestToPem: jest.fn(() => 'csrPem'),
      privateKeyToPem: jest.fn(() => 'privPem')
    },
    asn1: { Type: { UTF8: 'utf8' } },
    __mockCsr: mockCsr
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
});
