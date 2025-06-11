const request = require('supertest');
const express = require('express');

const controller = require('../src/controllers/certController');
jest.mock('../src/utils/logger', () => ({ error: jest.fn(), info: jest.fn(), debug: jest.fn() }));
const logger = require('../src/utils/logger');

jest.mock('../src/controllers/certController');

var mockConfig = {};
jest.mock('../src/resources/config', () => jest.fn(() => mockConfig));
Object.assign(mockConfig, {
  getValidator: jest.fn(() => ({ validateSchema: jest.fn(() => true) })),
  isInitialized: jest.fn(() => true),
});

const router = require('../src/routers/certRouter');

describe('certRouter', () => {
  let app;
  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use('/', router);
  });

  test('root reports readiness', async() => {
    const res = await request(app).get('/');
    expect(res.text).toBe('Ready');
  });

  test('post /new validates body', async() => {
    controller.newWebServerCertificate.mockResolvedValue({ ok: true });
    const res = await request(app).post('/new').send({ hostname: 'foo.example.com', passphrase: 'p' });
    expect(res.body).toEqual({ ok: true });
  });

  test('post /new rejects invalid body', async() => {
    mockConfig.getValidator.mockReturnValueOnce({ validateSchema: jest.fn(() => false) });
    const invalid = await request(app)
      .post('/new')
      .send({ invalid: true });
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
});
