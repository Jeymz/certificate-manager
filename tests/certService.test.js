jest.mock('../src/resources/certificateRequest');
jest.mock('../src/resources/ca');
jest.mock('../src/resources/revocation');
jest.mock('node-forge', () => {
  const actual = jest.requireActual('node-forge');
  return {
    ...actual,
    pki: {
      ...actual.pki,
      certificateFromPem: jest.fn(),
      publicKeyToPem: jest.fn(),
    },
  };
});
jest.mock('crypto', () => {
  const actual = jest.requireActual('crypto');
  return {
    ...actual,
    generateKeyPair: jest.fn((type, opts, cb) => cb(null, 'pub', 'priv')),
  };
});

const path = require('path');
const forge = require('node-forge');
const CertificateRequest = require('../src/resources/certificateRequest');
const CA = require('../src/resources/ca');
const revocation = require('../src/resources/revocation');
const service = require('../src/services/certService');

describe('certService', () => {
  beforeEach(() => {
    CertificateRequest.mockClear();
    CA.mockClear();
    revocation.getBySerial.mockReset();
    revocation.add.mockReset();
    CertificateRequest.mockImplementation(() => ({
      addAltNames: jest.fn(),
      sign: jest.fn(),
      setCertType: jest.fn(),
      verify: jest.fn(() => true),
      getCSR: jest.fn(() => 'csr'),
      getPrivateKey: jest.fn(() => 'priv'),
      getPkcs12Bundle: jest.fn(() => 'p12data'),
    }));
    CA.mockImplementation(() => ({
      unlockCA: jest.fn(),
      signCSR: jest.fn(() => ({ certificate: 'cert', serial: '1', expiration: new Date() })),
      getCertChain: jest.fn(() => 'chain'),
      getCACertificate: jest.fn(() => 'cacert'),
      updateLog: jest.fn(),
    }));
    revocation.getBySerial.mockResolvedValue({ serialNumber: '1', hostname: 'foo.example.com', expiration: new Date().toISOString(), revoked: false });
    revocation.add.mockResolvedValue();
  });

  test('newWebServerCertificate returns an error when CSR verification fails', async() => {
    CertificateRequest.mockImplementationOnce(() => ({
      addAltNames: jest.fn(),
      sign: jest.fn(),
      verify: jest.fn(() => false),
    }));
    const result = await service.newWebServerCertificate('foo.example.com', 'pass');
    expect(result).toEqual({ error: 'Unable to verify CSR' });
  });

  test('newIntermediateCA returns an error when CSR verification fails', async() => {
    CertificateRequest.mockImplementationOnce(() => ({
      setCertType: jest.fn(),
      sign: jest.fn(),
      verify: jest.fn(() => false),
    }));
    const fs = require('fs');
    jest.spyOn(fs.promises, 'mkdir').mockResolvedValue();
    jest.spyOn(fs.promises, 'writeFile').mockResolvedValue();
    const result = await service.newIntermediateCA('int.example.com', 'pass');
    expect(result).toEqual({ error: 'Unable to verify CSR' });
    fs.promises.mkdir.mockRestore();
    fs.promises.writeFile.mockRestore();
  });

  test('newLdapServerCertificate sets ldapServer type and returns an error when CSR verification fails', async() => {
    const req = {
      addAltNames: jest.fn(),
      sign: jest.fn(),
      setCertType: jest.fn(),
      verify: jest.fn(() => false),
    };
    CertificateRequest.mockImplementationOnce(() => req);
    const result = await service.newLdapServerCertificate('ldap.example.com', 'pass');
    expect(req.setCertType).toHaveBeenCalledWith('ldapServer');
    expect(result).toEqual({ error: 'Unable to verify CSR' });
  });

  test('newWebServerCertificate rejects root issuance when enforced', async() => {
    const orig = process.env.CONFIG_PATH;
    const cfg = path.join(__dirname, 'noIntermediate.json');
    jest.resetModules();
    process.env.CONFIG_PATH = cfg;
    const CR = require('../src/resources/certificateRequest');
    const CARes = require('../src/resources/ca');
    CR.mockImplementation(() => ({
      addAltNames: jest.fn(),
      sign: jest.fn(),
      setCertType: jest.fn(),
      verify: jest.fn(() => true),
      getPrivateKey: jest.fn(() => 'priv'),
      getPkcs12Bundle: jest.fn(() => 'p12data'),
    }));
    CARes.mockImplementation(() => ({
      unlockCA: jest.fn(),
      signCSR: jest.fn(() => ({ certificate: 'cert', serial: '1', expiration: new Date() })),
      getCertChain: jest.fn(() => 'chain'),
      getCACertificate: jest.fn(() => 'cacert'),
      updateLog: jest.fn(),
    }));
    const svc = require('../src/services/certService');
    const result = await svc.newWebServerCertificate('foo.example.com', 'pass');
    expect(result).toEqual({ error: 'Root CA may not issue leaf certs' });
    process.env.CONFIG_PATH = orig;
  });

  test('newLdapServerCertificate rejects root issuance when enforced', async() => {
    const orig = process.env.CONFIG_PATH;
    const cfg = path.join(__dirname, 'noIntermediate.json');
    jest.resetModules();
    process.env.CONFIG_PATH = cfg;
    const CR = require('../src/resources/certificateRequest');
    const CARes = require('../src/resources/ca');
    CR.mockImplementation(() => ({
      addAltNames: jest.fn(),
      sign: jest.fn(),
      setCertType: jest.fn(),
      verify: jest.fn(() => true),
      getPrivateKey: jest.fn(() => 'priv'),
      getPkcs12Bundle: jest.fn(() => 'p12data'),
    }));
    CARes.mockImplementation(() => ({
      unlockCA: jest.fn(),
      signCSR: jest.fn(() => ({ certificate: 'cert', serial: '1', expiration: new Date() })),
      getCertChain: jest.fn(() => 'chain'),
      getCACertificate: jest.fn(() => 'cacert'),
      updateLog: jest.fn(),
    }));
    const svc = require('../src/services/certService');
    const result = await svc.newLdapServerCertificate('ldap.example.com', 'pass');
    expect(result).toEqual({ error: 'Root CA may not issue leaf certs' });
    process.env.CONFIG_PATH = orig;
  });

  test('renewCertificate reissues with stored subject and SANs', async() => {
    const fs = require('fs');
    jest.spyOn(fs.promises, 'readFile').mockImplementation((file) => {
      if (file.includes('.cert.crt')) {
        return Promise.resolve('CERTDATA');
      }
      if (file.includes('.key.pem')) {
        return Promise.resolve('PRIVATEKEY');
      }
      return Promise.resolve('');
    });
    jest.spyOn(fs.promises, 'writeFile').mockResolvedValue();
    revocation.getBySerial.mockResolvedValue({ serialNumber: '10', hostname: 'foo.example.com', expiration: new Date().toISOString(), revoked: false });
    const mockCert = {
      subject: { getField: jest.fn(() => ({ value: 'foo.example.com' })) },
      extensions: [
        { name: 'subjectAltName', altNames: [{ type: 2, value: 'foo.example.com' }, { type: 7, ip: '127.0.0.1' }] },
        { name: 'extKeyUsage', serverAuth: true },
      ],
      publicKey: 'pub',
    };
    forge.pki.certificateFromPem.mockReturnValue(mockCert);
    forge.pki.publicKeyToPem.mockReturnValue('pubPEM');
    CA.mockImplementationOnce(() => ({
      unlockCA: jest.fn(),
      signCSR: jest.fn(() => ({ certificate: 'renewedCert', serial: '20', expiration: new Date('2030-01-01'), validityDaysApplied: 20 })),
      getCertChain: jest.fn(() => 'chain'),
      getCACertificate: jest.fn(() => 'cacert'),
      updateLog: jest.fn(),
    }));
    const result = await service.renewCertificate('10', 'pass', true, 'bundle', 20, 'actor');
    expect(result).toEqual({
      certificate: 'renewedCert',
      privateKey: 'PRIVATEKEY',
      hostname: 'foo.example.com',
      chain: 'renewedCertchain',
      p12: 'p12data',
    });
    expect(revocation.add).toHaveBeenCalledWith('20', 'foo.example.com', expect.any(String));
    expect(CertificateRequest).toHaveBeenCalledWith('foo.example.com', expect.objectContaining({ privateKeyPEM: 'PRIVATEKEY', publicKey: 'pubPEM' }));
    fs.promises.readFile.mockRestore();
    fs.promises.writeFile.mockRestore();
  });

  test('renewCertificate returns error when serial is missing', async() => {
    revocation.getBySerial.mockResolvedValueOnce(null);
    const result = await service.renewCertificate('99', 'pass');
    expect(result).toEqual({ error: 'Serial not found' });
  });

  test('renewCertificate returns error when certificate material is missing', async() => {
    const fs = require('fs');
    jest.spyOn(fs.promises, 'readFile').mockRejectedValue(new Error('missing'));
    const result = await service.renewCertificate('1', 'pass');
    expect(result).toEqual({ error: 'Original certificate material not found' });
    fs.promises.readFile.mockRestore();
  });

  test('renewCertificate returns error when entry is revoked', async() => {
    revocation.getBySerial.mockResolvedValueOnce({ serialNumber: '5', hostname: 'foo.example.com', revoked: true });
    const result = await service.renewCertificate('5', 'pass');
    expect(result).toEqual({ error: 'Certificate is revoked' });
  });

  test('renewCertificate enforces validity limits', async() => {
    const result = await service.renewCertificate('1', 'pass', false, null, 500);
    expect(result).toEqual({ error: 'validityDays must be between 1 and 397' });
  });

  test('renewCertificate applies profile default validity when provided', async() => {
    const fs = require('fs');
    jest.spyOn(fs.promises, 'readFile').mockImplementation((file) => {
      if (file.includes('.cert.crt')) {
        return Promise.resolve('CERTDATA');
      }
      if (file.includes('.key.pem')) {
        return Promise.resolve('PRIVATEKEY');
      }
      return Promise.resolve('');
    });
    jest.spyOn(fs.promises, 'writeFile').mockResolvedValue();
    forge.pki.certificateFromPem.mockReturnValue({
      subject: { getField: jest.fn(() => ({ value: 'foo.example.com' })) },
      extensions: [{ name: 'extKeyUsage', serverAuth: true }],
      publicKey: 'pub',
    });
    forge.pki.publicKeyToPem.mockReturnValue('pubPEM');
    const caInstance = {
      unlockCA: jest.fn(),
      signCSR: jest.fn(() => ({ certificate: 'renewed', serial: '30', expiration: new Date('2031-01-01'), validityDaysApplied: 15 })),
      getCertChain: jest.fn(() => 'chain'),
      getCACertificate: jest.fn(() => 'cacert'),
      updateLog: jest.fn(),
    };
    CA.mockImplementationOnce(() => caInstance);
    const result = await service.renewCertificate('10', 'pass');
    expect(caInstance.signCSR).toHaveBeenCalledWith(expect.anything(), { validityDays: 90 });
    expect(result.certificate).toBe('renewed');
    fs.promises.readFile.mockRestore();
    fs.promises.writeFile.mockRestore();
  });
});
