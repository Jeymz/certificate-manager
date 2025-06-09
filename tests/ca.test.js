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
      validity: {},
    })),
    certificateToPem: jest.fn(() => 'signedCert'),
  },
  md: { sha256: { create: jest.fn() } },
}));

let fs;
let CA;

beforeEach(() => {
  jest.resetModules();
  fs = require('fs');
  fs.promises = {
    readFile: jest.fn((file) => {
      if (file.includes('defaults.json')) {
        return Promise.resolve(JSON.stringify({
          server: { port: 3000 },
          storeDirectory: './files',
          subject: {},
          validDomains: ['example.com'],
          extensions: { webServer: [] },
        }));
      }
      if (file.includes('serial')) {
        return Promise.resolve('1');
      }
      if (file.includes('log.json')) {
        return Promise.resolve(JSON.stringify({ requests: [] }));
      }
      return Promise.resolve('dummy');
    }),
    writeFile: jest.fn(() => Promise.resolve()),
  };
  fs.readFileSync = jest.fn((file) => {
    if (file.includes('defaults.json')) {
      return JSON.stringify({
        server: { port: 3000 },
        storeDirectory: './files',
        subject: {},
        validDomains: ['example.com'],
        extensions: { webServer: [] },
      });
    }
    if (file.includes('serial')) {
      return '1';
    }
    if (file.includes('log.json')) {
      return JSON.stringify({ requests: [] });
    }
    return 'dummy';
  });
  fs.writeFileSync = jest.fn(() => {});
  fs.existsSync = jest.fn(() => false);
  CA = require('../src/resources/ca');
});

describe('CA resource', () => {
  test('unlockCA calls decrypt', async() => {
    const ca = await new CA();
    ca.unlockCA('pass');
    expect(require('node-forge').pki.decryptRsaPrivateKey).toHaveBeenCalled();
  });

  test('signCSR requires unlocked key', async() => {
    const ca = await new CA();
    const csr = { getCSR: () => 'csr', getHostname: () => 'foo.example.com', getCertType: () => 'webServer', getPrivateKey: () => 'priv' };
    await expect(ca.signCSR(csr)).rejects.toThrow();
    ca.unlockCA('pass');
    await expect(ca.signCSR(csr)).resolves.toBe('signedCert');
  });

  test('getSerial increments serial', async() => {
    const ca = await new CA();
    const serial = await ca.getSerial();
    expect(serial).toBe('2');
  });

  test('constructor loads intermediate when provided', async() => {
    const ca = await new CA('intermediate');
    expect(fs.promises.readFile).toHaveBeenCalledWith(expect.stringContaining('intermediates/intermediate.cert.crt'), 'utf-8');
  });
});
