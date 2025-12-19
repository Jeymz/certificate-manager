jest.mock('../src/resources/certificateRequest');
jest.mock('../src/resources/ca');

jest.mock('../src/utils/logger', () => ({
  error: jest.fn(),
  info: jest.fn(),
  debug: jest.fn(),
  audit: { info: jest.fn() },
}));

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
const logger = require('../src/utils/logger');

describe('audit logging', () => {
  beforeEach(() => {
    const fs = require('fs');
    jest.spyOn(fs.promises, 'writeFile').mockResolvedValue();
    jest.spyOn(fs.promises, 'mkdir').mockResolvedValue();
    CertificateRequest.mockClear();
    CA.mockClear();
    logger.audit.info.mockClear();
    CertificateRequest.mockImplementation(() => ({
      addAltNames: jest.fn(),
      sign: jest.fn(),
      setCertType: jest.fn(),
      verify: jest.fn(() => true),
      getCSR: jest.fn(() => 'csr'),
      getPrivateKey: jest.fn(() => 'priv'),
      getPkcs12Bundle: jest.fn(() => 'p12'),
    }));
    CA.mockImplementation(() => ({
      unlockCA: jest.fn(),
      signCSR: jest.fn(() => ({ certificate: 'cert', serial: '1', expiration: new Date() })),
      getCertChain: jest.fn(() => 'chain'),
      getCACertificate: jest.fn(() => 'cacert'),
      updateLog: jest.fn(),
    }));
  });

  afterEach(() => {
    const fs = require('fs');
    fs.promises.writeFile.mockRestore();
    fs.promises.mkdir.mockRestore();
  });

  test('logs certificate issuance with metadata', async() => {
    await service.newWebServerCertificate('foo.example.com', 'pass', false, false, null, null, '1.2.3.4');
    expect(logger.audit.info).toHaveBeenCalled();
    const evt = logger.audit.info.mock.calls[0][0];
    expect(evt.eventType).toBe('CERT_ISSUE');
    expect(evt.subject).toBe('foo.example.com');
    expect(evt.serialNumber).toBe('1');
    expect(evt.performedBy).toBe('1.2.3.4');
  });

  test('handles missing performer', async() => {
    await service.newWebServerCertificate('foo.example.com', 'pass');
    const evt = logger.audit.info.mock.calls[0][0];
    expect(evt.performedBy).toBeUndefined();
  });
});
