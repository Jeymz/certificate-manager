jest.mock('../src/resources/certificateRequest');
jest.mock('../src/resources/ca');
jest.mock('crypto', () => {
  const actual = jest.requireActual('crypto');
  return {
    ...actual,
    generateKeyPair: jest.fn((type, opts, cb) => cb(null, 'pub', 'priv')),
  };
});

const path = require('path');
const CertificateRequest = require('../src/resources/certificateRequest');
const CA = require('../src/resources/ca');
const service = require('../src/services/certService');

describe('certService', () => {
  beforeEach(() => {
    CertificateRequest.mockClear();
    CA.mockClear();
    CertificateRequest.mockImplementation(() => ({
      addAltNames: jest.fn(),
      sign: jest.fn(),
      setCertType: jest.fn(),
      verify: jest.fn(() => true),
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
});
