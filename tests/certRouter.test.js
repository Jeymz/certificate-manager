const request = require('supertest');
const express = require('express');

const controller = require('../src/controllers/certController');

jest.mock('../src/controllers/certController');

const configMock = {
  getValidator: jest.fn(() => ({ validateSchema: jest.fn(() => true) })),
  isInitialized: jest.fn(() => true)
};

jest.mock('../src/resources/config', () => jest.fn(() => configMock));

const routerFactory = require('../src/routers/certRouter');

describe('certRouter', () => {
  let app;
  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use('/', routerFactory());
  });

  test('root reports readiness', async () => {
    const res = await request(app).get('/');
    expect(res.text).toBe('Ready');
  });

  test('post /new validates body', async () => {
    controller.newWebServerCertificate.mockReturnValue({ ok: true });
    const res = await request(app).post('/new').send({ hostname: 'foo.example.com', passphrase: 'p' });
    expect(res.body).toEqual({ ok: true });
  });
});
