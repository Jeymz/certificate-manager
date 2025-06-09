const fs = require('fs').promises;
const path = require('path');
const forge = require('node-forge');

jest.setTimeout(80000);

let createCA;
let createIntermediate;
let controller;

beforeAll(async() => {
  jest.setTimeout(30000);
  jest.resetModules();
  process.env.CAPASS = 'pass';
  await fs.mkdir(path.join(__dirname, '../files'), { recursive: true });
  createCA = require('../scripts/setup');
  createIntermediate = require('../scripts/setup-intermediate');
  controller = require('../src/controllers/certController');
  await createCA();
  const intDir = path.join(__dirname, '../files/intermediates');
  await createIntermediate('intermediate.example.com', 'pass');
  await fs.rename(
    path.join(intDir, 'intermediate.example.com.cert.crt'),
    path.join(intDir, 'intermediate.cert.crt'),
  );
  await fs.rename(
    path.join(intDir, 'intermediate.example.com.key.pem'),
    path.join(intDir, 'intermediate.key.pem'),
  );
});

afterAll(async() => {
  await fs.rm(path.join(__dirname, '../files'), { recursive: true, force: true });
  await fs.rm(path.join(__dirname, '../config/defaults.json'), { force: true });
});

test('intermediate certificate validates with root CA', async() => {
  const rootPem = await fs.readFile(path.join(__dirname, '../files/certs/ca.cert.crt'), 'utf-8');
  const intermediatePem = await fs.readFile(path.join(__dirname, '../files/intermediates/intermediate.cert.crt'), 'utf-8');
  const rootCert = forge.pki.certificateFromPem(rootPem);
  const intermediateCert = forge.pki.certificateFromPem(intermediatePem);
  const caStore = forge.pki.createCaStore([rootCert]);
  const verified = forge.pki.verifyCertificateChain(caStore, [intermediateCert]);
  expect(verified).toBe(true);
});

test('web server certificate validates with root CA', async() => {
  const { certificate } = await controller.newWebServerCertificate('server.example.com', 'pass');
  const rootPem = await fs.readFile(path.join(__dirname, '../files/certs/ca.cert.crt'), 'utf-8');
  const intermediatePem = await fs.readFile(path.join(__dirname, '../files/intermediates/intermediate.cert.crt'), 'utf-8');
  const rootCert = forge.pki.certificateFromPem(rootPem);
  const intermediateCert = forge.pki.certificateFromPem(intermediatePem);
  const serverCert = forge.pki.certificateFromPem(certificate);
  const caStore = forge.pki.createCaStore([rootCert]);
  const verified = forge.pki.verifyCertificateChain(caStore, [serverCert, intermediateCert]);
  expect(verified).toBe(true);
});
