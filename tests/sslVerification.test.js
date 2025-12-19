const fs = require('fs').promises;
const path = require('path');
const forge = require('node-forge');

jest.setTimeout(80000);

let createCA;
let createIntermediate;
let controller;

beforeAll(async() => {
  // jest.setTimeout(30000);
  jest.resetModules();
  process.env.CAPASS = 'pass';
  await fs.mkdir(path.join(__dirname, '../files_test'), { recursive: true });
  createCA = require('../scripts/setup');
  createIntermediate = require('../scripts/setup-intermediate');
  controller = require('../src/controllers/certController');
  await createCA();
  const intDir = path.join(__dirname, '../files_test/intermediates');
  await createIntermediate('intermediateCA.example.com', 'pass');
});

afterAll(async() => {
  await fs.rm(path.join(__dirname, '../files_test'), { recursive: true, force: true });
  await fs.rm(path.join(__dirname, '../config/test.json'), { force: true });
});

test('intermediate certificate validates with root CA', async() => {
  const rootPem = await fs.readFile(path.join(__dirname, '../files_test/certs/ca.cert.crt'), 'utf-8');
  const intermediatePem = await fs.readFile(path.join(__dirname, '../files_test/intermediates/intermediateCA.example.com.cert.crt'), 'utf-8');
  const rootCert = forge.pki.certificateFromPem(rootPem);
  const intermediateCert = forge.pki.certificateFromPem(intermediatePem);
  const caStore = forge.pki.createCaStore([rootCert]);
  const verified = forge.pki.verifyCertificateChain(caStore, [intermediateCert]);
  expect(verified).toBe(true);
});

test('web server certificate validates with root CA', async() => {
  const { chain } = await controller.newWebServerCertificate('server.example.com', 'pass');
  const rootPem = await fs.readFile(path.join(__dirname, '../files_test/certs/ca.cert.crt'), 'utf-8');
  const rootCert = forge.pki.certificateFromPem(rootPem);
  const chainCerts = chain.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g);
  const serverCert = forge.pki.certificateFromPem(chainCerts[0]);
  const intermediateCert = forge.pki.certificateFromPem(chainCerts[1]);
  const caStore = forge.pki.createCaStore([rootCert]);
  const verified = forge.pki.verifyCertificateChain(caStore, [serverCert, intermediateCert]);
  expect(verified).toBe(true);
});

test('ldap server certificate includes required extensions', async() => {
  const { certificate } = await controller.newLdapServerCertificate('ldap.example.com', 'pass', ['ldap.example.com']);
  const cert = forge.pki.certificateFromPem(certificate);
  const eku = cert.extensions.find(e => e.name === 'extKeyUsage');
  expect(eku.clientAuth).toBe(true);
  expect(eku.serverAuth).toBe(true);
  const san = cert.extensions.find(e => e.name === 'subjectAltName');
  const dnsNames = san.altNames.filter(n => n.type === 2).map(n => n.value);
  expect(dnsNames).toContain('ldap.example.com');
});
