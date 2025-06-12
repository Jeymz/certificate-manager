const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const CertificateRequest = require('../src/resources/certificateRequest');
const CA = require('../src/resources/ca');
const config = require('../src/resources/config')();
const logger = require('../src/utils/logger');

async function createIntermediate(name, passphrase, intermediatePassphrase) {
  const options = {
    modulusLength: 4096,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  };
  if (intermediatePassphrase) {
    options.privateKeyEncoding.cipher = 'aes-256-cbc';
    options.privateKeyEncoding.passphrase = intermediatePassphrase;
  }
  const keypair = await new Promise((resolve, reject) => {
    crypto.generateKeyPair('rsa', options, (err, publicKey, privateKey) => {
      if (err) {
        reject(err);
      } else {
        resolve({ publicKey, privateKey });
      }
    });
  });
  const csr = new CertificateRequest(name, {
    publicKey: keypair.publicKey,
    privateKeyPEM: keypair.privateKey,
    passphrase: intermediatePassphrase,
  });
  csr.setCertType('intermediateCA');
  csr.sign();
  if (!csr.verify()) {
    throw new Error('Unable to verify CSR');
  }
  const ca = await new CA();
  ca.unlockCA(passphrase);
  const { certificate } = await ca.signCSR(csr);
  const privateKey = keypair.privateKey;
  const intDir = path.join(config.getStoreDirectory(), 'intermediates');
  await fs.mkdir(intDir, { recursive: true });
  await fs.writeFile(path.join(intDir, `${name}.cert.crt`), certificate, { encoding: 'utf-8' });
  await fs.writeFile(path.join(intDir, `${name}.key.pem`), privateKey, { encoding: 'utf-8' });
  logger.info(`Intermediate CA '${name}' created.`);
  return { certificate, privateKey, name };
}

if (require.main === module) {
  const [name] = process.argv.slice(2);
  if (/^[a-zA-Z0-9_.-]+$/.test(name) === false) {
    logger.error('Invalid name: must be alphanumeric, underscores, dashes, or dots.');
    process.exit(1);
  }
  if (!name || !process.env.CAPASS || !process.env.INTPASS) {
    logger.error('Usage: CAPASS=rootpass INTPASS=intpass node setup-intermediate.js <name>');
    process.exit(1);
  }
  createIntermediate(name, process.env.CAPASS, process.env.INTPASS).catch((err) => {
    logger.error(err.message);
    process.exit(1);
  });
}

module.exports = createIntermediate;
