const forge = require('node-forge');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const config = require('../src/resources/config')();

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
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
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
  console.log('Certificate created.');

  // PEM-format keys and cert
  const pem = {
    privateKey: forge.pki.privateKeyToPem(keys.privateKey),
    publicKey: forge.pki.publicKeyToPem(keys.publicKey),
    certificate: forge.pki.certificateToPem(cert)
  };

  console.log('\nKey-Pair:');
  console.log(pem.privateKey);
  console.log(pem.publicKey);

  console.log('\nCertificate:');
  console.log(pem.certificate);

  fs.writeFileSync(path.join(__dirname, '../', 'files', 'private', 'ca.key.pem'), keypair.privateKey, 'utf-8');
  fs.writeFileSync(path.join(__dirname, '../', 'files', 'public', 'ca.pubkey.pem'), keypair.publicKey, 'utf-8');
  fs.writeFileSync(path.join(__dirname, '../', 'files', 'certs', 'ca.cert.crt'), pem.certificate, 'utf-8');
  fs.writeFileSync(path.join(__dirname, '../', 'files', 'log.json'), JSON.stringify({
    requests: []
  }), 'utf-8');
  fs.writeFileSync(path.join(__dirname, '../', 'files', 'serial'), '1000000', 'utf-8');
}

if (Object.keys(process.env).indexOf('CAPASS') < 0 || typeof process.env.CAPASS !== 'string') {
  console.log('Please set an environment variable called CAPASS before running setup');
} else {
  createCA();
}
