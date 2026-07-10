const request = require('supertest');
const express = require('express');

jest.mock('../src/controllers/certController', () => ({
  newWebServerCertificate: jest.fn(),
  newLdapServerCertificate: jest.fn(),
  newIntermediateCA: jest.fn(),
  revokeCertificate: jest.fn(),
  getCRL: jest.fn(),
}));
const controller = require('../src/controllers/certController');

jest.mock('../src/utils/logger', () => ({ error: jest.fn(), info: jest.fn(), debug: jest.fn(), audit: { info: jest.fn() } }));
const logger = require('../src/utils/logger');

describe('profile validity enforcement', () => {
  let app;
  const mockConfig = {
    getValidator: jest.fn(() => ({ validateSchema: jest.fn(() => true) })),
    isInitialized: jest.fn(() => true),
    getStoreDirectory: jest.fn(() => './files_test'),
    getValidityLimits: jest.fn(() => ({ minDays: 1, maxDays: 397 })),
    getProfileValidity: jest.fn(() => null),
  };

  jest.mock('../src/resources/config', () => jest.fn(() => mockConfig));

  beforeEach(() => {
    const router = require('../src/routers/certRouter');
    // deepcode ignore DisablePoweredBy/test: Not relevant to test
    app = express();
    app.use(express.json());
    app.use('/', router);
  });

  afterEach(() => {
    controller.newWebServerCertificate.mockReset();
    logger.error.mockClear();
    mockConfig.getProfileValidity.mockImplementation(() => null);
    mockConfig.getValidityLimits.mockImplementation(() => ({ minDays: 1, maxDays: 397 }));
  });

  test('uses profileMetadata default validityDays when present and within limits', async() => {
    mockConfig.getProfileValidity.mockImplementation(() => 90);
    controller.newWebServerCertificate.mockResolvedValue({ ok: true });

    const res = await request(app).post('/new').send({ hostname: 'foo.example.com', passphrase: 'p' });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
    expect(controller.newWebServerCertificate).toHaveBeenCalledWith('foo.example.com', 'p', undefined, undefined, undefined, 90, expect.any(String));
  });

  test('accepts request validityDays when within global limits', async() => {
    mockConfig.getProfileValidity.mockImplementation(() => null);
    mockConfig.getValidityLimits.mockImplementation(() => ({ minDays: 1, maxDays: 397 }));
    controller.newWebServerCertificate.mockResolvedValue({ ok: true });

    const res = await request(app).post('/new').send({ hostname: 'foo.example.com', passphrase: 'p', validityDays: 30 });
    expect(res.status).toBe(200);
    expect(controller.newWebServerCertificate).toHaveBeenCalledWith('foo.example.com', 'p', undefined, undefined, undefined, 30, expect.any(String));
  });

  test('rejects profile default when outside global limits (server error)', async() => {
    mockConfig.getProfileValidity.mockImplementation(() => 9999);
    mockConfig.getValidityLimits.mockImplementation(() => ({ minDays: 1, maxDays: 397 }));
    controller.newWebServerCertificate.mockResolvedValue({ ok: true });

    const res = await request(app).post('/new').send({ hostname: 'foo.example.com', passphrase: 'p' });
    expect(res.status).toBe(500);
    expect(res.body).toEqual({ error: 'Invalid server configuration for profile validity' });
  });

  test('rejects request validityDays outside global limits (bad request)', async() => {
    mockConfig.getProfileValidity.mockImplementation(() => null);
    mockConfig.getValidityLimits.mockImplementation(() => ({ minDays: 1, maxDays: 50 }));
    controller.newWebServerCertificate.mockResolvedValue({ ok: true });

    const res = await request(app).post('/new').send({ hostname: 'foo.example.com', passphrase: 'p', validityDays: 90 });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'validityDays must be between 1 and 50' });
  });
});
