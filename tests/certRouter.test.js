const request = require('supertest');
const express = require('express');

jest.mock('../src/controllers/certController', () => ({
  newWebServerCertificate: jest.fn(),
  newIntermediateCA: jest.fn(),
  revokeCertificate: jest.fn(),
  getCRL: jest.fn(),
}));
const controller = require('../src/controllers/certController');
jest.mock('../src/utils/logger', () => ({ error: jest.fn(), info: jest.fn(), debug: jest.fn() }));
const logger = require('../src/utils/logger');

var mockConfig = {
  getValidator: jest.fn(() => ({ validateSchema: jest.fn(() => true) })),
  isInitialized: jest.fn(() => true),
  getStoreDirectory: jest.fn(() => './files_test'),
};
jest.mock('../src/resources/config', () => jest.fn(() => mockConfig));

const router = require('../src/routers/certRouter');

describe('certRouter', () => {
  let app;
  beforeEach(() => {
    // file deepcode ignore DisablePoweredBy/test: this is a functionality test, not intended for production data
    app = express();
    app.use(express.json());
    app.use('/', router);
  });

  test('root reports readiness', async() => {
    const res = await request(app).get('/');
    expect(res.text).toBe('Ready');
  });

  test('root reports awaiting setup when not initialized', async() => {
    mockConfig.isInitialized.mockReturnValueOnce(false);
    const res = await request(app).get('/');
    expect(res.text).toBe('Awaiting Setup');
  });

  test('post /new validates body', async() => {
    controller.newWebServerCertificate.mockResolvedValue({ ok: true });
    // file deepcode ignore NoHardcodedPasswords/test: this is a functionality test, not intended for production data
    const res = await request(app).post('/new').send({ hostname: 'foo.example.com', passphrase: 'p', bundleP12: true, password: 'pass' });
    expect(res.body).toEqual({ ok: true });
    expect(controller.newWebServerCertificate).toHaveBeenCalledWith('foo.example.com', 'p', undefined, true, 'pass');
  });

  test('post /new rejects invalid body', async() => {
    mockConfig.getValidator.mockReturnValueOnce({ validateSchema: jest.fn(() => false) });
    const invalid = await request(app)
      .post('/new')
      .send({ invalid: true });
    expect(invalid.status).toBe(400);
  });

  test('post /new rejects non-object body', async() => {
    const invalid = await request(app)
      .post('/new')
      .set('Content-Type', 'application/json')
      .send('"bad"');
    expect(invalid.status).toBe(400);
  });

  test('invalid passphrase handled gracefully', async() => {
    controller.newWebServerCertificate.mockImplementation(() => {
      throw new Error('CA Key is locked');
    });
    const res = await request(app)
      .post('/new')
      .send({ hostname: 'foo.example.com', passphrase: 'bad' });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'Unable to process request' });
    expect(logger.error).toHaveBeenCalled();
  });

  test('post /intermediate forwards to controller', async() => {
    controller.newIntermediateCA.mockResolvedValue({ ok: true });
    const res = await request(app)
      .post('/intermediate')
      .send({ hostname: 'intermediate.example.com', passphrase: 'p', intermediatePassphrase: 'int' });
    expect(res.body).toEqual({ ok: true });
    expect(controller.newIntermediateCA).toHaveBeenCalledWith('intermediate.example.com', 'p', 'int');
  });

  test('post /intermediate rejects non-object body', async() => {
    const res = await request(app)
      .post('/intermediate')
      .set('Content-Type', 'application/json')
      .send('"bad"');
    expect(res.status).toBe(400);
  });

  test('post /intermediate rejects invalid body', async() => {
    mockConfig.getValidator.mockReturnValueOnce({ validateSchema: jest.fn(() => false) });
    const res = await request(app).post('/intermediate').send({});
    expect(res.status).toBe(400);
  });

  test('post /intermediate handles controller error', async() => {
    controller.newIntermediateCA.mockImplementation(() => { throw new Error('fail'); });
    const res = await request(app).post('/intermediate').send({ hostname: 'i', passphrase: 'p' });
    expect(res.status).toBe(400);
    expect(logger.error).toHaveBeenCalled();
  });

  test('post /revoke forwards to controller', async() => {
    controller.revokeCertificate.mockResolvedValue({ revoked: true });
    const res = await request(app)
      .post('/revoke')
      .send({ serialNumber: '1', reason: 'KeyCompromise' });
    expect(res.body).toEqual({ revoked: true });
    expect(controller.revokeCertificate).toHaveBeenCalledWith('1', 'KeyCompromise');
  });

  test('post /revoke rejects non-object body', async() => {
    const res = await request(app)
      .post('/revoke')
      .set('Content-Type', 'application/json')
      .send('"bad"');
    expect(res.status).toBe(400);
  });

  test('post /revoke rejects invalid body', async() => {
    mockConfig.getValidator.mockReturnValueOnce({ validateSchema: jest.fn(() => false) });
    const res = await request(app).post('/revoke').send({});
    expect(res.status).toBe(400);
  });

  test('post /revoke handles controller error', async() => {
    controller.revokeCertificate.mockImplementation(() => { throw new Error('fail'); });
    const res = await request(app).post('/revoke').send({ serialNumber: '1' });
    expect(res.status).toBe(400);
    expect(logger.error).toHaveBeenCalled();
  });

  test('post /revoke returns 404 when not found', async() => {
    controller.revokeCertificate.mockResolvedValue({ error: 'Serial not found' });
    const res = await request(app)
      .post('/revoke')
      .send({ serialNumber: '99' });
    expect(res.status).toBe(404);
  });

  test('get /crl returns data', async() => {
    controller.getCRL.mockResolvedValue({ revoked: [] });
    const res = await request(app).get('/crl');
    expect(res.body).toEqual({ revoked: [] });
  });

  test('get /crl handles errors', async() => {
    controller.getCRL.mockImplementation(() => { throw new Error('fail'); });
    const res = await request(app).get('/crl');
    expect(res.status).toBe(400);
    expect(logger.error).toHaveBeenCalled();
  });
});
