const config = require('../src/resources/config')();
const crlService = require('../src/services/crlService');
const logger = require('../src/utils/logger');

function resolveTarget() {
  const explicitIssuer = process.env.CRL_ISSUER;
  if (explicitIssuer === 'root') {
    return {
      issuerKey: 'root',
      passphrase: process.env.CAPASS,
      intermediateOverride: null,
    };
  }
  if (explicitIssuer === 'defaultIntermediate') {
    return {
      issuerKey: 'defaultIntermediate',
      passphrase: process.env.INTPASS,
      intermediateOverride: config.getDefaultIntermediate(),
    };
  }

  const activeIssuerKey = config.getActiveRevocationIssuerKey();
  if (activeIssuerKey === 'defaultIntermediate') {
    return {
      issuerKey: activeIssuerKey,
      passphrase: process.env.INTPASS,
      intermediateOverride: config.getDefaultIntermediate(),
    };
  }
  return {
    issuerKey: 'root',
    passphrase: process.env.CAPASS,
    intermediateOverride: null,
  };
}

async function publishCrl() {
  const { issuerKey, passphrase, intermediateOverride } = resolveTarget();
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new Error(`Missing passphrase for ${issuerKey} CRL publication`);
  }
  const outputPath = await crlService.publishPemCrl(passphrase, intermediateOverride);
  logger.info(`Published ${issuerKey} CRL to ${outputPath}`);
}

if (require.main === module) {
  publishCrl().catch((err) => {
    logger.error(err.message);
    process.exit(1);
  });
}

module.exports = publishCrl;
