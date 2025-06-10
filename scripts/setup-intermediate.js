const fs = require('fs').promises;
const path = require('path');
const CertificateRequest = require('../src/resources/certificateRequest');
const CA = require('../src/resources/ca');
const config = require('../src/resources/config')();
const logger = require('../src/utils/logger');

async function createIntermediate(name, passphrase) {
  const csr = new CertificateRequest(name);
  csr.setCertType('intermediateCA');
  csr.sign();
  if (!csr.verify()) {
    throw new Error('Unable to verify CSR');
  }
  const ca = await new CA();
  ca.unlockCA(passphrase);
  const certificate = await ca.signCSR(csr);
  const privateKey = csr.getPrivateKey();
  const intDir = path.join(config.getStoreDirectory(), 'intermediates');
  await fs.mkdir(intDir, { recursive: true });
  await fs.writeFile(path.join(intDir, `${name}.cert.crt`), certificate, { encoding: 'utf-8' });
  await fs.writeFile(path.join(intDir, `${name}.key.pem`), privateKey, { encoding: 'utf-8' });
  logger.info(`Intermediate CA '${name}' created.`);
  return { certificate, privateKey, name };
}

if (require.main === module) {
  const [name] = process.argv.slice(2);
  if (!name || !process.env.CAPASS) {
    logger.error('Usage: CAPASS=pass node setup-intermediate.js <name>');
    process.exit(1);
  }
  createIntermediate(name, process.env.CAPASS).catch((err) => {
    logger.error(err.message);
    process.exit(1);
  });
}

module.exports = createIntermediate;
