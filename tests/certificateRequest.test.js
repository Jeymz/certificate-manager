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
      certificateFromPem: jest.fn(() => 'certObj'),
      decryptRsaPrivateKey: jest.fn(() => 'unlocked'),
      encryptedPrivateKeyFromPem: jest.fn(() => 'encInfo'),
      decryptPrivateKeyInfo: jest.fn(() => 'decInfo'),
      privateKeyFromAsn1: jest.fn(() => 'unlocked'),
      privateKeyFromPem: jest.fn(() => 'pemKey'),
    },
    pkcs12: { toPkcs12Asn1: jest.fn(() => 'asn1') },
    asn1: {
      Type: { UTF8: 'utf8' },
      toDer: jest.fn(() => ({ getBytes: jest.fn(() => 'bytes') })),
    },
    __mockCsr: mockCsr,
  };
});

const CertificateRequest = require('../src/resources/certificateRequest');

describe('certificateRequest', () => {
  test('hostname stored lowercase', () => {
    const req = new CertificateRequest('Foo.EXAMPLE.com');
    expect(req.getHostname()).toBe('foo.example.com');
  });

  test('constructor decrypts provided key', () => {
    const req = new CertificateRequest('foo.example.com', { publicKey: 'pub', privateKeyPEM: 'privPem', passphrase: 'pass' });
    expect(req.getPrivateKey()).toBe('privPem');
    const forge = require('node-forge');
    expect(forge.pki.decryptRsaPrivateKey).toHaveBeenCalled();
  });

  test('constructor rejects invalid hostname', () => {
    expect(() => new CertificateRequest('badhost')).toThrow('Invalid hostname: badhost');
  });

  test('sign generates csr', () => {
    const req = new CertificateRequest('foo.example.com');
    req.sign();
    expect(req.getCSR()).toBe('csrPem');
  });

  test('verify proxies to csr', () => {
    const req = new CertificateRequest('foo.example.com');
    req.sign();
    expect(req.verify()).toBe(true);
    expect(require('node-forge').__mockCsr.verify).toHaveBeenCalled();
  });

  test('setCertType validates input', () => {
    const req = new CertificateRequest('foo.example.com');
    expect(() => req.setCertType('invalid')).toThrow();
    req.setCertType('webServer');
    expect(req.getCertType()).toBe('webServer');
  });

  test('addAltNames adds SAN extension', () => {
    const req = new CertificateRequest('foo.example.com');
    req.addAltNames(['bar.example.com']);
    req.sign();
    expect(require('node-forge').__mockCsr.setAttributes).toHaveBeenCalled();
  });

  test('invalid SAN entries are ignored', () => {
    const forge = require('node-forge');
    forge.__mockCsr.setAttributes.mockClear();
    const req = new CertificateRequest('foo.example.com');
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
    const req = new CertificateRequest('foo.example.com');
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

  test('getPkcs12Bundle returns base64 string', () => {
    const forge = require('node-forge');
    const req = new CertificateRequest('foo.example.com');
    const result = req.getPkcs12Bundle('certPem', 'chainPem', 'pass');
    expect(forge.pkcs12.toPkcs12Asn1).toHaveBeenCalled();
    expect(typeof result).toBe('string');
  });
});
