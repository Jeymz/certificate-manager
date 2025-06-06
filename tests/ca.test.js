jest.mock('fs');
jest.mock('node-forge', () => ({
  pki: {
    decryptRsaPrivateKey: jest.fn(() => 'unlocked'),
    certificationRequestFromPem: jest.fn(() => ({ verify: () => true, subject: { attributes: [] }, attributes: [] })),
    certificateFromPem: jest.fn(() => ({ subject: { attributes: [] } })),
    createCertificate: jest.fn(() => ({
      setExtensions: jest.fn(),
      sign: jest.fn(),
      setSubject: jest.fn(),
      setIssuer: jest.fn(),
      validity: {}
    })),
    certificateToPem: jest.fn(() => 'signedCert')
  },
  md: { sha256: { create: jest.fn() } }
}));

const fs = require('fs');
const CA = require('../src/resources/ca');

beforeEach(() => {
  fs.readFileSync.mockImplementation((file) => {
    if (file.includes('defaults.json')) {
      return JSON.stringify({
        server: { port: 3000 },
        storeDirectory: './files',
        subject: {},
        validDomains: ['example.com'],
        extensions: { webServer: [] }
      });
    }
    return 'dummy';
  });
  fs.writeFileSync.mockImplementation(() => {});
  fs.existsSync = jest.fn(() => false);
});

describe('CA resource', () => {
  test('unlockCA calls decrypt', () => {
    const ca = new CA();
    ca.unlockCA('pass');
    expect(require('node-forge').pki.decryptRsaPrivateKey).toHaveBeenCalled();
  });

  test('signCSR requires unlocked key', () => {
    const ca = new CA();
    const csr = { getCSR: () => 'csr', getHostname: () => 'foo.example.com', getCertType: () => 'webServer', getPrivateKey: () => 'priv' };
    expect(() => ca.signCSR(csr)).toThrow();
    ca.unlockCA('pass');
    expect(ca.signCSR(csr)).toBe('signedCert');
  });

  test('getSerial increments serial', () => {
    const ca = new CA();
    fs.readFileSync.mockReturnValueOnce('1');
    const serial = ca.getSerial();
    expect(serial).toBe('2');
  });
});
