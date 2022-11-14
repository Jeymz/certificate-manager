const forge = require('node-forge');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const { subjectAttributes, extensions, config } = require('../src/resources/main');

function createRootCA(passphrase) {
  const options = {
    modulusLength: 4096,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase
    }
  };
  const keypair = crypto.generateKeyPairSync('rsa', options);
  const keys = {
    privateKey: forge.pki.decryptRsaPrivateKey(
      keypair.privateKey,
      passphrase
    ),
    publicKey: forge.pki.publicKeyFromPem(keypair.publicKey)
  };
  // Add some logging here
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '1000000';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 3);
  const attributes = subjectAttributes();
  const subjectConfig = config.get('certificate');
  attributes.push({
    shortName: 'CN',
    value: `${subjectConfig.organization} - ROOT CA`
  });
  cert.setSubject(attributes);
  cert.setIssuer(attributes);
  cert.setExtensions(extensions.rootCA);

  cert.sign(keys.privateKey, forge.md.sha256.create());
  const pem = {
    privateKey: forge.pki.privateKeyToPem(keys.privateKey),
    publicKey: forge.pki.publicKeyToPem(keys.publicKey),
    certificate: forge.pki.certificateToPem(cert)
  };

  const caConfig = config.get('ca');
  
}