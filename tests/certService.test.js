jest.mock('../src/resources/certificateRequest');
jest.mock('../src/resources/ca');
jest.mock('crypto', () => {
  const actual = jest.requireActual('crypto');
  return {
    ...actual,
    generateKeyPair: jest.fn((type, opts, cb) => cb(null, 'pub', 'priv')),
  };
});

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
      signCSR: jest.fn(() => 'cert'),
      getCertChain: jest.fn(() => 'chain'),
    }));
  });

  test('newWebServerCertificate returns error when verify fails', async() => {
    CertificateRequest.mockImplementationOnce(() => ({
      addAltNames: jest.fn(),
      sign: jest.fn(),
      verify: jest.fn(() => false),
    }));
    const result = await service.newWebServerCertificate('foo.example.com', 'pass');
    expect(result).toEqual({ error: 'Unable to verify CSR' });
  });

  test('newIntermediateCA returns error when verify fails', async() => {
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
});
