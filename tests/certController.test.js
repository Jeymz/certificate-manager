// Keep revocation and crypto controlled in tests; mock CertificateRequest and CA for stable controller tests
jest.mock('../src/resources/certificateRequest');
jest.mock('../src/resources/ca');
jest.mock('../src/resources/revocation');
jest.mock('../src/services/crlService');
jest.mock('crypto', () => {
  const actual = jest.requireActual('crypto');
  return {
    ...actual,
    generateKeyPair: jest.fn((type, opts, cb) => cb(null, 'pub', 'priv')),
  };
});

const CertificateRequest = require('../src/resources/certificateRequest');
const CA = require('../src/resources/ca');
const revocation = require('../src/resources/revocation');
const controller = require('../src/controllers/certController');
const config = require('../src/resources/config')();
const crlService = require('../src/services/crlService');
const service = require('../src/services/certService');

describe('certController', () => {
  beforeEach(() => {
    CertificateRequest.mockClear();
    CA.mockClear();
    CertificateRequest.mockImplementation(() => ({
      addAltNames: jest.fn(),
      sign: jest.fn(),
      setCertType: jest.fn(),
      verify: jest.fn(() => true),
      getPrivateKey: jest.fn(() => 'priv'),
      getCSR: jest.fn(() => 'csr'),
      getHostname: jest.fn(() => 'foo.example.com'),
      getCertType: jest.fn(() => 'webServer'),
      getPkcs12Bundle: jest.fn(() => 'p12data'),
    }));
    CA.mockImplementation(() => ({
      unlockCA: jest.fn(),
      signCSR: jest.fn(() => ({ certificate: 'cert', serial: '1', expiration: new Date() })),
      getCACertificate: jest.fn(() => 'caCert'),
      getCertChain: jest.fn(() => 'caCertroot'),
      updateLog: jest.fn(),
    }));
    const fs = require('fs');
    jest.spyOn(fs.promises, 'writeFile').mockResolvedValue();
    jest.spyOn(fs.promises, 'mkdir').mockResolvedValue();
    revocation.revoke.mockReset();
    revocation.getRevoked.mockReset();
    revocation.getActiveRevoked.mockReset();
    crlService.generatePemCrl.mockReset();
    crlService.publishPemCrl.mockReset();
    crlService.getPublishedPemCrl.mockReset();
  });

  afterEach(() => {
    const fs = require('fs');
    fs.promises.writeFile.mockRestore();
    fs.promises.mkdir.mockRestore();
  });

  test('newWebServerCertificate returns data', async() => {
    const result = await controller.newWebServerCertificate('foo.example.com', 'pass');
    expect(result).toEqual({ certificate: 'cert', privateKey: 'priv', hostname: 'foo.example.com', chain: 'certcaCertroot' });
    expect(CA).toHaveBeenCalledWith('intermediateCA.example.com');
  });

  test('returns error when CSR verification fails', async() => {
    CertificateRequest.mockImplementation(() => ({
      addAltNames: jest.fn(),
      sign: jest.fn(),
      setCertType: jest.fn(),
      verify: jest.fn(() => false),
      getPrivateKey: jest.fn(() => 'priv'),
      getCSR: jest.fn(() => 'csr'),
      getHostname: jest.fn(() => 'foo.example.com'),
      getCertType: jest.fn(() => 'webServer'),
      getPkcs12Bundle: jest.fn(() => 'p12data'),
    }));
    const result = await controller.newWebServerCertificate('bad.example.com', 'pass');
    expect(result).toEqual({ error: 'Unable to verify CSR' });
  });

  test('rejects issuance when requireIntermediate is true and no default configured', async() => {
    const spyDefault = jest.spyOn(config, 'getDefaultIntermediate').mockReturnValueOnce(null);
    const spyRequire = jest.spyOn(config, 'getRequireIntermediate').mockReturnValueOnce(true);
    const result = await controller.newWebServerCertificate('foo.example.com', 'pass');
    expect(result).toEqual({ error: 'Root CA may not issue leaf certs' });
    spyDefault.mockRestore();
    spyRequire.mockRestore();
  });

  test('alt names passed to request', async() => {
    await controller.newWebServerCertificate('foo.example.com', 'pass', ['alt.example.com']);
    expect(CertificateRequest).toHaveBeenCalledWith('foo.example.com');
    expect(CertificateRequest.mock.results[0].value.addAltNames).toHaveBeenCalledWith(['alt.example.com']);
  });

  test('p12 bundle returned when requested', async() => {
    const result = await controller.newWebServerCertificate('foo.example.com', 'pass', false, true, 'p12pass');
    expect(result.p12).toBe('p12data');
    expect(CertificateRequest.mock.results[0].value.getPkcs12Bundle).toHaveBeenCalledWith('cert', 'caCertroot', 'p12pass');
  });

  test('p12 bundle written to disk when requested', async() => {
    const fs = require('fs');
    await controller.newWebServerCertificate('foo.example.com', 'pass', false, true, 'p12pass');
    expect(fs.promises.writeFile).toHaveBeenCalledWith(
      expect.stringContaining('foo.example.com.bundle.p12'),
      expect.any(Buffer),
      expect.objectContaining({ mode: 0o600 }),
    );
  });

  test('newIntermediateCA writes files', async() => {
    const fs = require('fs');
    const result = await controller.newIntermediateCA('intermediate.example.com', 'pass', 'intpass');
    expect(result).toEqual({ certificate: 'cert', privateKey: 'priv', hostname: 'intermediate.example.com' });
    expect(fs.promises.writeFile).toHaveBeenCalled();
  });

  test('revokeCertificate returns success', async() => {
    revocation.revoke.mockResolvedValue({});
    crlService.publishPemCrl.mockResolvedValue('files_test/crl/root-ca.crl.pem');
    const result = await controller.revokeCertificate('1', 'KeyCompromise', 'secret');
    expect(result).toEqual({ revoked: true });
    expect(revocation.revoke).toHaveBeenCalledWith('1', 'KeyCompromise', undefined);
    expect(crlService.publishPemCrl).toHaveBeenCalledWith('secret');
  });

  test('revokeCertificate handles missing serial', async() => {
    revocation.revoke.mockResolvedValue(null);
    const result = await controller.revokeCertificate('99');
    expect(result).toEqual({ error: 'Serial not found' });
  });

  test('getCRL returns revoked list', async() => {
    revocation.getActiveRevoked.mockResolvedValue([{ serialNumber: '1' }]);
    const result = await controller.getCRL();
    expect(result).toEqual({ revoked: [{ serialNumber: '1' }] });
  });

  test('getCRLPem returns PEM output', async() => {
    crlService.getPublishedPemCrl.mockResolvedValue('PEM DATA');
    const result = await controller.getCRLPem();
    expect(result).toBe('PEM DATA');
    expect(crlService.getPublishedPemCrl).toHaveBeenCalled();
  });

  test('newLdapServerCertificate sets LDAP cert type', async() => {
    await controller.newLdapServerCertificate('ldap.example.com', 'pass', ['alt.example.com']);
    expect(CertificateRequest).toHaveBeenCalledWith('ldap.example.com');
    const reqInstance = CertificateRequest.mock.results[0].value;
    expect(reqInstance.setCertType).toHaveBeenCalledWith('ldapServer');
    expect(reqInstance.addAltNames).toHaveBeenCalledWith(['alt.example.com']);
  });

  test('renewCertificate forwards to service', async() => {
    const spy = jest.spyOn(service, 'renewCertificate').mockResolvedValue({ renewed: true });
    const result = await controller.renewCertificate('1', 'pass', true, 'bundle', 15, 'actor');
    expect(result).toEqual({ renewed: true });
    expect(spy).toHaveBeenCalledWith('1', 'pass', true, 'bundle', 15, 'actor');
    spy.mockRestore();
  });
});
