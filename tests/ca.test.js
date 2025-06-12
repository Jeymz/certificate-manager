jest.mock('fs');
jest.mock('node-forge', () => ({
  pki: {
    decryptRsaPrivateKey: jest.fn(() => 'unlocked'),
    encryptedPrivateKeyFromPem: jest.fn(() => 'encInfo'),
    decryptPrivateKeyInfo: jest.fn(() => 'decInfo'),
    privateKeyFromAsn1: jest.fn(() => 'unlocked'),
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
jest.mock('../src/utils/logger', () => ({ error: jest.fn(), debug: jest.fn(), info: jest.fn() }));

const path = require('path');
let fs;
let CA;

beforeEach(() => {
  jest.resetModules();
  fs = require('fs');
  const configFile = path.basename(process.env.CONFIG_PATH);
  fs.promises = {
    readFile: jest.fn((file) => {
      if (file.includes(configFile)) {
        return Promise.resolve(JSON.stringify({
          server: { port: 3000 },
          storeDirectory: './files_test',
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
    if (file.includes(configFile)) {
      return JSON.stringify({
        server: { port: 3000 },
        storeDirectory: './files_test',
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

  test('unlockCA falls back to pkcs8 decrypt', async() => {
    const forge = require('node-forge');
    forge.pki.decryptRsaPrivateKey.mockReturnValueOnce(null);
    const ca = await new CA();
    ca.unlockCA('pass');
    expect(forge.pki.decryptPrivateKeyInfo).toHaveBeenCalled();
    expect(forge.pki.privateKeyFromAsn1).toHaveBeenCalled();
  });

  test('unlockCA logs error when pkcs8 decrypt fails', async() => {
    const forge = require('node-forge');
    const logger = require('../src/utils/logger');
    forge.pki.decryptRsaPrivateKey.mockReturnValueOnce(null);
    forge.pki.decryptPrivateKeyInfo.mockImplementationOnce(() => { throw new Error('fail'); });
    const ca = await new CA();
    ca.unlockCA('pass');
    expect(logger.error).toHaveBeenCalled();
  });

  test('signCSR requires unlocked key', async() => {
    const ca = await new CA();
    const csr = { getCSR: () => 'csr', getHostname: () => 'foo.example.com', getCertType: () => 'webServer', getPrivateKey: () => 'priv', attributes: [] };
    await expect(ca.signCSR(csr)).rejects.toThrow();
    ca.unlockCA('pass');
    const result = await ca.signCSR(csr);
    expect(result.certificate).toBe('signedCert');
    expect(typeof result.serial).toBe('string');
    expect(result.expiration instanceof Date).toBe(true);
  });

  test('signCSR merges alt names', async() => {
    const ca = await new CA();
    ca.unlockCA('pass');
    const csr = {
      getCSR: () => 'csr',
      getHostname: () => 'foo.example.com',
      getCertType: () => 'webServer',
      getPrivateKey: () => 'priv',
    };
    const forge = require('node-forge');
    forge.pki.certificationRequestFromPem.mockReturnValueOnce({
      verify: () => true,
      subject: { attributes: [] },
      attributes: [{ name: 'extensionRequest', extensions: [{ name: 'subjectAltName' }] }],
      publicKey: 'pub',
    });
    await ca.signCSR(csr);
    const certObj = forge.pki.createCertificate.mock.results[0].value;
    expect(certObj.setExtensions).toHaveBeenCalledWith(expect.arrayContaining([
      expect.objectContaining({ name: 'subjectAltName' }),
    ]));
  });

  test('signCSR rejects invalid CSR', async() => {
    const ca = await new CA();
    ca.unlockCA('pass');
    const csr = { getCSR: () => 'csr', getHostname: () => 'foo.example.com', getCertType: () => 'webServer', getPrivateKey: () => 'priv' };
    const forge = require('node-forge');
    forge.pki.certificationRequestFromPem.mockReturnValueOnce({ verify: () => false });
    await expect(ca.signCSR(csr)).rejects.toThrow('CSR verification failed');
  });

  test('getSerial increments serial', async() => {
    const ca = await new CA();
    const serial = await ca.getSerial();
    expect(serial).toBe('2');
  });

  test('constructor loads intermediate when provided', async() => {
    await new CA('intermediate');
    const path = require('path');
    const expectedPath = path.join('intermediates', 'intermediate.cert.crt');
    expect(fs.promises.readFile).toHaveBeenCalledWith(expect.stringContaining(expectedPath), 'utf-8');
  });

  test('getCertChain returns chain', async() => {
    const ca = await new CA('intermediate');
    const chain = ca.getCertChain();
    expect(typeof chain).toBe('string');
  });

  test('getCertChain returns single cert when root', async() => {
    const ca = await new CA();
    const chain = ca.getCertChain();
    expect(chain).toBe('dummy');
  });
});
