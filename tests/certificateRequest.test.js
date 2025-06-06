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
    asn1: { Type: { UTF8: 'utf8' } }
  };
});

const Request = require('../src/resources/certificateRequest');

describe('certificateRequest', () => {
  test('hostname stored lowercase', () => {
    const req = new Request('Foo.EXAMPLE.com');
    expect(req.getHostname()).toBe('foo.example.com');
  });

  test('sign generates csr', () => {
    const req = new Request('foo.example.com');
    req.sign();
    expect(req.getCSR()).toBe('csrPem');
  });

  test('setCertType validates input', () => {
    const req = new Request('foo.example.com');
    expect(() => req.setCertType('invalid')).toThrow();
    req.setCertType('webServer');
    expect(req.getCertType()).toBe('webServer');
  });
});
