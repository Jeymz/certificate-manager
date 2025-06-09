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
  });

  test('alt names passed to request', async() => {
    await controller.newWebServerCertificate('foo.example.com', 'pass', ['alt.example.com']);
    expect(CSR).toHaveBeenCalledWith('foo.example.com');
    expect(CSR.mock.results[0].value.addAltNames).toHaveBeenCalledWith(['alt.example.com']);
  });
});
