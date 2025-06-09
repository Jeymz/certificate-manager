jest.mock('../src/resources/certificateRequest');
jest.mock('../src/resources/ca');

const CertificateRequest = require('../src/resources/certificateRequest');
const CA = require('../src/resources/ca');
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
      getHostname: jest.fn(() => 'foo.example.com'),
      getCertType: jest.fn(() => 'webServer'),
    }));
    CA.mockImplementation(() => ({
      unlockCA: jest.fn(),
      signCSR: jest.fn(() => 'cert'),
    }));
  });

  test('newWebServerCertificate returns data', async() => {
    const result = await controller.newWebServerCertificate('foo.example.com', 'pass');
    expect(result).toEqual({ certificate: 'cert', privateKey: 'priv', hostname: 'foo.example.com' });
    expect(CA).toHaveBeenCalledWith('intermediate');
  });

  test('alt names passed to request', async() => {
    await controller.newWebServerCertificate('foo.example.com', 'pass', ['alt.example.com']);
    expect(CertificateRequest).toHaveBeenCalledWith('foo.example.com');
    expect(CertificateRequest.mock.results[0].value.addAltNames).toHaveBeenCalledWith(['alt.example.com']);
  });

  test('newIntermediateCA writes files', async() => {
    const fs = require('fs');
    jest.spyOn(fs.promises, 'mkdir').mockResolvedValue();
    jest.spyOn(fs.promises, 'writeFile').mockResolvedValue();
    const result = await controller.newIntermediateCA('intermediate.example.com', 'pass');
    expect(result).toEqual({ certificate: 'cert', privateKey: 'priv', hostname: 'intermediate.example.com' });
    expect(fs.promises.writeFile).toHaveBeenCalled();
    fs.promises.mkdir.mockRestore();
    fs.promises.writeFile.mockRestore();
  });
});
