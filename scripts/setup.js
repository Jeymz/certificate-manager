const crypto = require('crypto');
const forge = require('node-forge');
const fs = require('fs');
const path = require('path');
const { createTracing } = require('trace_events');

const files = path.resolve('./files');
const subjectDetails = {
  CN: 'Robotti Tech Services - Root CA',
  E: 'admin@robotti.io',
  O: 'Robotti Tech Services LLC.',
  L: 'Fairfield',
  ST: 'Ohio',
  C: 'US'
}

// TODO: This needs to call proper functions
function createRootCA(passphrase = false) {
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
  }
  if (passphrase) {
    options.privateKeyEncoding.cipher = 'aes-256-cbc',
    options.privateKeyEncoding.passphrase = passphrase.toString();
  }
  const keypair = crypto.generateKeyPairSync('rsa', options);
  fs.writeFileSync(path.join(files, 'private', 'ca.key.pem'), keypair.privateKey, 'utf-8');
  fs.writeFileSync(path.join(files, 'public', 'ca.pubkey.pem'), keypair.publicKey, 'utf-8');

  const pki = forge.pki;
  
  const keyData = {
    publicKey: pki.publicKeyFromPem(keypair.publicKey.toString())
  }
  if (passphrase) {
    keyData.privateKey = pki.decryptRsaPrivateKey(
      keypair.privateKey.toString(),
      passphrase
    )
  } else {
    keyData.privateKey = pki.privateKeyFromPem(keypair.privateKey.toString())
  }
  console.log(keyData.privateKey);
  const { privateKey, publicKey } = keyData;
  const cert = pki.createCertificate()
  cert.publicKey = publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(
    cert.validity.notBefore.getFullYear() + 1
  );
  const attributes = []
  Object.keys(subjectDetails).forEach((key) => {
    attributes.push({
      shortName: key,
      value: subjectDetails[key]
    });
  });
  cert.setSubject(attributes);
  cert.setIssuer(attributes);
  cert.sign(privateKey, forge.md.sha256.create());
  const certificate = pki.certificateToPem(cert);
  fs.writeFileSync(path.join(files, 'certs', 'ca.cert.pem'), certificate, 'utf-8');
  return 'done'
}

// TODO: Add proper prompts for setup
if (process.env.CAPASS) {
  console.log(createRootCA(process.env.CAPASS.toString().trim()));
} else {
  console.log(createRootCA());
}