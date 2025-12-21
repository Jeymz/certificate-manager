jest.mock('../src/resources/ca');
jest.mock('../src/resources/revocation');
jest.mock('../src/resources/config', () => () => ({
  getDefaultIntermediate: jest.fn(() => null),
  getStoreDirectory: jest.fn(() => './files_test'),
}));
jest.mock('../src/resources/crlNumber');
jest.mock('../src/utils/logger', () => ({
  debug: jest.fn(),
  info: jest.fn(),
}));

const forge = require('node-forge');
const CA = require('../src/resources/ca');
const revocation = require('../src/resources/revocation');
const crlNumberStore = require('../src/resources/crlNumber');

const crlService = require('../src/services/crlService');

function buildTestCa() {
  const keypair = forge.pki.rsa.generateKeyPair({ bits: 1024, e: 0x10001 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = keypair.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date(Date.now() + 3600 * 1000);
  cert.setSubject([{ name: 'commonName', value: 'Test CA' }]);
  cert.setIssuer(cert.subject.attributes);
  cert.setExtensions([{ name: 'basicConstraints', cA: true }]);
  cert.sign(keypair.privateKey, forge.md.sha256.create());
  return { keypair, pem: forge.pki.certificateToPem(cert) };
}

describe('crlService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    crlNumberStore.nextCrlNumber.mockResolvedValue(1);
  });

  test('generatePemCrl produces a PEM encoded CRL with active entries', async() => {
    const { keypair, pem } = buildTestCa();
    const caStub = {
      unlockCA: jest.fn(),
      getPrivateKey: jest.fn(() => keypair.privateKey),
      getCACertificate: jest.fn(() => pem),
    };
    CA.mockImplementation(() => Promise.resolve(caStub));
    revocation.getActiveRevoked.mockResolvedValue([
      { serialNumber: '10', revokedAt: '2024-01-01T00:00:00Z', reason: 'keyCompromise' },
    ]);
    crlNumberStore.nextCrlNumber.mockResolvedValue(42);

    const pemCrl = await crlService.generatePemCrl('secret');

    expect(pemCrl).toContain('BEGIN X509 CRL');
    const decoded = forge.pem.decode(pemCrl)[0];
    const asn1 = forge.asn1.fromDer(decoded.body);
    const tbs = asn1.value[0];
    const revokedSequence = tbs.value[5];
    const entry = revokedSequence.value[0];
    const serialHex = forge.util.bytesToHex(entry.value[0].value);
    expect(serialHex).toBe(BigInt(10).toString(16).padStart(2, '0'));
    const extensionsWrapper = tbs.value[tbs.value.length - 1];
    const extensions = extensionsWrapper.value[0];
    const crlNumberExtension = extensions.value.find(
      (ext) => forge.asn1.derToOid(ext.value[0].value) === '2.5.29.20',
    );
    const crlNumber = forge.asn1.fromDer(crlNumberExtension.value[1].value);
    const crlNumberHex = forge.util.bytesToHex(crlNumber.value);
    expect(parseInt(crlNumberHex, 16)).toBe(42);
    expect(crlNumberStore.nextCrlNumber).toHaveBeenCalled();
    expect(caStub.unlockCA).toHaveBeenCalled();
  });

  test('generatePemCrl handles empty revocation list', async() => {
    const { keypair, pem } = buildTestCa();
    const caStub = {
      unlockCA: jest.fn(),
      getPrivateKey: jest.fn(() => keypair.privateKey),
      getCACertificate: jest.fn(() => pem),
    };
    CA.mockImplementation(() => Promise.resolve(caStub));
    revocation.getActiveRevoked.mockResolvedValue([]);

    const pemCrl = await crlService.generatePemCrl('secret');
    expect(pemCrl).toContain('BEGIN X509 CRL');
  });

  test('generatePemCrl rejects missing passphrase', async() => {
    await expect(crlService.generatePemCrl()).rejects.toThrow('CA passphrase required for CRL generation');
  });
});
