jest.mock('../src/resources/certificateRequest');
jest.mock('../src/resources/ca');
jest.mock('../src/resources/revocation');
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
  });

  afterEach(() => {
    const fs = require('fs');
    fs.promises.writeFile.mockRestore();
    fs.promises.mkdir.mockRestore();
  });

  test('newWebServerCertificate returns data', async() => {
    const result = await controller.newWebServerCertificate('foo.example.com', 'pass');
    expect(result).toEqual({ certificate: 'cert', privateKey: 'priv', hostname: 'foo.example.com', chain: 'certcaCertroot' });
    expect(CA).toHaveBeenCalledWith('intermediate');
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

  test('newIntermediateCA writes files', async() => {
    const fs = require('fs');
    const result = await controller.newIntermediateCA('intermediate.example.com', 'pass', 'intpass');
    expect(result).toEqual({ certificate: 'cert', privateKey: 'priv', hostname: 'intermediate.example.com' });
    expect(fs.promises.writeFile).toHaveBeenCalled();
  });

  test('revokeCertificate returns success', async() => {
    revocation.revoke.mockResolvedValue({});
    const result = await controller.revokeCertificate('1', 'KeyCompromise');
    expect(result).toEqual({ revoked: true });
    expect(revocation.revoke).toHaveBeenCalledWith('1', 'KeyCompromise');
  });

  test('revokeCertificate handles missing serial', async() => {
    revocation.revoke.mockResolvedValue(null);
    const result = await controller.revokeCertificate('99');
    expect(result).toEqual({ error: 'Serial not found' });
  });

  test('getCRL returns revoked list', async() => {
    revocation.getRevoked.mockResolvedValue([{ serialNumber: '1' }]);
    const result = await controller.getCRL();
    expect(result).toEqual({ revoked: [{ serialNumber: '1' }] });
  });
});
