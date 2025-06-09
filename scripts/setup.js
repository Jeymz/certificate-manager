const fs = require('fs').promises;
const crypto = require('crypto');
const path = require('path');
const forge = require('node-forge');
const config = require('../src/resources/config')();
const logger = require('../src/utils/logger');

const CA_VALIDITY_YEARS = process.env.CA_VALIDITY_YEARS || 5;

async function createCA() {
  const options = {
    modulusLength: 4096,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  };
  if (process.env.CAPASS) {
    options.privateKeyEncoding.cipher = 'aes-256-cbc';
    options.privateKeyEncoding.passphrase = process.env.CAPASS.toString().trim();
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
  const keys = {
    privateKey: forge.pki.decryptRsaPrivateKey(
      keypair.privateKey,
      process.env.CAPASS.toString().trim(),
    ),
    publicKey: forge.pki.publicKeyFromPem(keypair.publicKey),
  };
  logger.info('Generated RSA key pair for CA.');
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '1000000';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + CA_VALIDITY_YEARS);
  const attrs = config.getSubject();
  attrs.push({
    shortName: 'CN',
    value: 'Robotti Tech Services - Root CA',
  });
  cert.setSubject(attrs);
  cert.setIssuer(attrs);

  cert.setExtensions([{
    name: 'basicConstraints',
    cA: true,
  }, {
    name: 'subjectKeyIdentifier',
  }, {
    name: 'authorityKeyIdentifier',
  }]);

  // self-sign certificate
  cert.sign(keys.privateKey, forge.md.sha256.create());

  // PEM-format keys and cert
  const pem = {
    privateKey: forge.pki.privateKeyToPem(keys.privateKey),
    publicKey: forge.pki.publicKeyToPem(keys.publicKey),
    certificate: forge.pki.certificateToPem(cert),
  };

  try {
    await fs.access(config.getStoreDirectory());
  } catch {
    logger.error(`Store directory does not exist: ${config.getStoreDirectory()}`);
    throw new Error('Invalid store directory provided');
  }

  async function ensureDir(dir) {
    try {
      await fs.access(dir);
    } catch {
      await fs.mkdir(dir, { recursive: true });
    }
  }

  await ensureDir(path.join(config.getStoreDirectory(), 'private'));
  await ensureDir(path.join(config.getStoreDirectory(), 'public'));
  await ensureDir(path.join(config.getStoreDirectory(), 'certs'));
  await ensureDir(path.join(config.getStoreDirectory(), 'requests'));
  await ensureDir(path.join(config.getStoreDirectory(), 'newCerts'));

  await fs.writeFile(path.join(config.getStoreDirectory(), 'private', 'ca.key.pem'), keypair.privateKey, { encoding: 'utf-8' });
  await fs.writeFile(path.join(config.getStoreDirectory(), 'public', 'ca.pubkey.pem'), keypair.publicKey, { encoding: 'utf-8' });
  await fs.writeFile(path.join(config.getStoreDirectory(), 'certs', 'ca.cert.crt'), pem.certificate, { encoding: 'utf-8' });
  await fs.writeFile(path.join(config.getStoreDirectory(), 'log.json'), JSON.stringify({
    requests: [],
  }), { encoding: 'utf-8' });
  await fs.writeFile(path.join(config.getStoreDirectory(), 'serial'), '1000000', { encoding: 'utf-8' });
  logger.info('CA created successfully.');
}

if (Object.keys(process.env).indexOf('CAPASS') < 0 || typeof process.env.CAPASS !== 'string') {
  logger.error('CAPASS environment variable must be set to create a new CA.');
  process.exit(1);
}
createCA().catch((err) => {
  logger.error(err.message);
  process.exit(1);
});

module.exports = createCA;
