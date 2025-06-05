const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const forge = require('node-forge');
const config = require('../src/resources/config')();

const CA_VALIDITY_YEARS = process.env.CA_VALIDITY_YEARS || 5;

function createCA() {
  const options = {
    modulusLength: 4096,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  };
  if (process.env.CAPASS) {
    options.privateKeyEncoding.cipher = 'aes-256-cbc';
    options.privateKeyEncoding.passphrase = process.env.CAPASS.toString().trim();
  }
  const keypair = crypto.generateKeyPairSync('rsa', options);
  const keys = {
    privateKey: forge.pki.decryptRsaPrivateKey(
      keypair.privateKey,
      process.env.CAPASS.toString().trim()
    ),
    publicKey: forge.pki.publicKeyFromPem(keypair.publicKey)
  };
  console.log('Key-pair created.');
  console.log('Creating self-signed certificate...');
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '1000000';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + CA_VALIDITY_YEARS);
  const attrs = config.getSubject();
  attrs.push({
    shortName: 'CN',
    value: 'Robotti Tech Services - Root CA'
  });
  cert.setSubject(attrs);
  cert.setIssuer(attrs);

  cert.setExtensions([{
    name: 'basicConstraints',
    cA: true
  }, {
    name: 'subjectKeyIdentifier'
  }, {
    name: 'authorityKeyIdentifier'
  }]);

  // self-sign certificate
  cert.sign(keys.privateKey, forge.md.sha256.create());

  // PEM-format keys and cert
  const pem = {
    privateKey: forge.pki.privateKeyToPem(keys.privateKey),
    publicKey: forge.pki.publicKeyToPem(keys.publicKey),
    certificate: forge.pki.certificateToPem(cert)
  };

  if (!fs.existsSync(config.getStoreDirectory())) {
    throw new Error('Invalid store directory provided');
  }
  if (!fs.existsSync(path.join(config.getStoreDirectory(), 'private'))) {
    fs.mkdirSync(path.join(config.getStoreDirectory(), 'private'));
  }
  if (!fs.existsSync(path.join(config.getStoreDirectory(), 'public'))) {
    fs.mkdirSync(path.join(config.getStoreDirectory(), 'public'));
  }
  if (!fs.existsSync(path.join(config.getStoreDirectory(), 'certs'))) {
    fs.mkdirSync(path.join(config.getStoreDirectory(), 'certs'));
  }
  if (!fs.existsSync(path.join(config.getStoreDirectory(), 'requests'))) {
    fs.mkdirSync(path.join(config.getStoreDirectory(), 'requests'));
  }
  if (!fs.existsSync(path.join(config.getStoreDirectory(), 'newCerts'))) {
    fs.mkdirSync(path.join(config.getStoreDirectory(), 'newCerts'));
  }
  fs.writeFileSync(path.join(config.getStoreDirectory(), 'private', 'ca.key.pem'), keypair.privateKey, { encoding: 'utf-8' });
  fs.writeFileSync(path.join(config.getStoreDirectory(), 'public', 'ca.pubkey.pem'), keypair.publicKey, { encoding: 'utf-8' });
  fs.writeFileSync(path.join(config.getStoreDirectory(), 'certs', 'ca.cert.crt'), pem.certificate, { encoding: 'utf-8' });
  fs.writeFileSync(path.join(config.getStoreDirectory(), 'log.json'), JSON.stringify({
    requests: []
  }), { encoding: 'utf-8' });
  fs.writeFileSync(path.join(config.getStoreDirectory(), 'serial'), '1000000', { encoding: 'utf-8' });
  console.log('Certificate created.');
}

if (Object.keys(process.env).indexOf('CAPASS') < 0 || typeof process.env.CAPASS !== 'string') {
  console.log('Please set an environment variable called CAPASS before running setup');
} else {
  createCA();
}
