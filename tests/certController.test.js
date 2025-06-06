jest.mock('../src/resources/certificateRequest');
jest.mock('../src/resources/ca');

const CSR = require('../src/resources/certificateRequest');
const CA = require('../src/resources/ca');
const controller = require('../src/controllers/certController');

describe('certController', () => {
  beforeEach(() => {
    CSR.mockClear();
    CA.mockClear();
    CSR.mockImplementation(() => ({
      addAltNames: jest.fn(),
      sign: jest.fn(),
      verify: jest.fn(() => true),
      getPrivateKey: jest.fn(() => 'priv'),
      getHostname: jest.fn(() => 'foo.example.com'),
      getCertType: jest.fn(() => 'webServer')
    }));
    CA.mockImplementation(() => ({
      unlockCA: jest.fn(),
      signCSR: jest.fn(() => 'cert')
    }));
  });

  test('newWebServerCertificate returns data', () => {
    const result = controller.newWebServerCertificate('foo.example.com', 'pass');
    expect(result).toEqual({ certificate: 'cert', privateKey: 'priv', hostname: 'foo.example.com' });
  });
});
