const fs = require('fs').promises;
const path = require('path');
const forge = require('node-forge');
const revocation = require('../resources/revocation');
const CA = require('../resources/ca');
const crlNumberStore = require('../resources/crlNumber');
const config = require('../resources/config')();
const logger = require('../utils/logger');

const SHA256_WITH_RSA_OID = '1.2.840.113549.1.1.11';

const reasonCodes = {
  unspecified: 0,
  keyCompromise: 1,
  cACompromise: 2,
  affiliationChanged: 3,
  superseded: 4,
  cessationOfOperation: 5,
  certificateHold: 6,
  removeFromCRL: 8,
  privilegeWithdrawn: 9,
  aACompromise: 10,
};

function pad(value) {
  return value.toString().padStart(2, '0');
}

function buildUTCTime(date) {
  const utc = `${String(date.getUTCFullYear()).slice(-2)}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
  return forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.UTCTIME, false, utc);
}

function algorithmIdentifier() {
  return forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.OID,
      false,
      forge.asn1.oidToDer(SHA256_WITH_RSA_OID).getBytes(),
    ),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, ''),
  ]);
}

function serialToInteger(serialNumber) {
  const hex = BigInt(serialNumber).toString(16).padStart(2, '0');
  const bytes = forge.util.hexToBytes(hex);
  return forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false, bytes);
}

function buildReasonExtension(reason) {
  if (!reason) {
    return null;
  }
  const normalized = reason.replace(/\s+/g, '').charAt(0).toLowerCase() + reason.replace(/\s+/g, '').slice(1);
  const code = reasonCodes[normalized];
  if (typeof code === 'undefined') {
    return null;
  }
  const reasonValue = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.ENUMERATED,
    false,
    forge.asn1.integerToDer(code).getBytes(),
  );
  const octetString = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.OCTETSTRING,
    false,
    forge.asn1.toDer(reasonValue).getBytes(),
  );
  return forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.OID,
      false,
      forge.asn1.oidToDer('2.5.29.21').getBytes(),
    ),
    octetString,
  ]);
}

function buildRevokedEntries(entries) {
  if (!entries.length) {
    return null;
  }
  const revokedAsn1 = entries.map((entry) => {
    const revokedOn = entry.revokedAt ? new Date(entry.revokedAt) : new Date();
    const reasonExtension = buildReasonExtension(entry.reason);
    const sequenceChildren = [
      serialToInteger(entry.serialNumber),
      buildUTCTime(revokedOn),
    ];
    if (reasonExtension) {
      const extensions = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [reasonExtension]);
      sequenceChildren.push(
        forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [extensions]),
      );
    }
    return forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, sequenceChildren);
  });
  return forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, revokedAsn1);
}

function buildCrlNumberExtension(crlNumber) {
  const numberAsn1 = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.INTEGER,
    false,
    forge.asn1.integerToDer(crlNumber).getBytes(),
  );
  const octetString = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.OCTETSTRING,
    false,
    forge.asn1.toDer(numberAsn1).getBytes(),
  );
  return forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.OID,
      false,
      forge.asn1.oidToDer('2.5.29.20').getBytes(),
    ),
    octetString,
  ]);
}

async function buildTbsList(issuer, revokedEntries, crlNumber) {
  const now = new Date();
  const nextUpdate = new Date(now.getTime() + 3600 * 1000);
  const revoked = buildRevokedEntries(revokedEntries);
  const children = [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false, '\u0001'),
    algorithmIdentifier(),
    issuer,
    buildUTCTime(now),
    buildUTCTime(nextUpdate),
  ];
  if (revoked) {
    children.push(revoked);
  }
  const extensions = forge.asn1.create(
    forge.asn1.Class.CONTEXT_SPECIFIC,
    0,
    true,
    [forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.SEQUENCE,
      true,
      [buildCrlNumberExtension(crlNumber)],
    )],
  );
  children.push(extensions);
  return forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, children);
}

async function signCrl(tbsCertList, caKey) {
  const derTbs = forge.asn1.toDer(tbsCertList).getBytes();
  const md = forge.md.sha256.create();
  md.update(derTbs, 'binary');
  const signature = caKey.sign(md);
  const signatureBitString = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.BITSTRING,
    false,
    String.fromCharCode(0x00) + signature,
  );
  return forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    tbsCertList,
    algorithmIdentifier(),
    signatureBitString,
  ]);
}

function getIssuerContext(intermediateOverride = undefined) {
  const issuerKey = intermediateOverride === null
    ? 'root'
    : (typeof intermediateOverride === 'string' && intermediateOverride.length > 0
      ? 'defaultIntermediate'
      : config.getActiveRevocationIssuerKey());
  const intermediateName = issuerKey === 'defaultIntermediate'
    ? (typeof intermediateOverride === 'string' && intermediateOverride.length > 0
      ? intermediateOverride
      : config.getDefaultIntermediate())
    : null;
  const issuerConfig = config.getRevocationIssuerConfig(issuerKey);
  if (!issuerConfig) {
    const err = new Error(`Revocation publishing is not configured for issuer ${issuerKey}`);
    err.code = 'CRL_CONFIG_MISSING';
    throw err;
  }
  return { issuerKey, intermediateName, issuerConfig };
}

module.exports = {
  /**
   * Generate a PEM encoded certificate revocation list signed by the CA.
   *
   * @returns {Promise<string>} PEM formatted CRL.
   */
  async generatePemCrl(passphrase, intermediateOverride = undefined) {
    if (typeof passphrase !== 'string' || passphrase.length === 0) {
      throw new Error('CA passphrase required for CRL generation');
    }
    const { intermediateName } = getIssuerContext(intermediateOverride);
    const activeRevocations = await revocation.getActiveRevoked();
    const crlNumber = await crlNumberStore.nextCrlNumber();
    const ca = await new CA(intermediateName);
    ca.unlockCA(passphrase, 'CRL_GENERATION');
    const caKey = ca.getPrivateKey();
    if (!caKey) {
      throw new Error('Unable to unlock CA key for CRL generation');
    }
    const caCertificate = forge.pki.certificateFromPem(ca.getCACertificate());
    const issuer = forge.pki.distinguishedNameToAsn1(caCertificate.subject);
    const tbsList = await buildTbsList(issuer, activeRevocations, crlNumber);
    const crlAsn1 = await signCrl(tbsList, caKey);
    const der = forge.asn1.toDer(crlAsn1).getBytes();
    const pem = forge.pem.encode({ type: 'X509 CRL', body: der });
    logger.info('Generated CRL with active revocations', { count: activeRevocations.length });
    return pem;
  },

  /**
   * Generate and persist the PEM encoded CRL for the active issuer.
   *
   * @param {string} passphrase - Passphrase to unlock the CRL-signing CA key.
   * @param {string|undefined} [intermediateOverride] - Optional intermediate name to sign with.
   * @returns {Promise<string>} Absolute path to the published CRL.
   */
  async publishPemCrl(passphrase, intermediateOverride = undefined) {
    const { intermediateName, issuerConfig } = getIssuerContext(intermediateOverride);
    const pem = await this.generatePemCrl(passphrase, intermediateName);
    const outputPath = path.join(config.getStoreDirectory(), issuerConfig.relativePath);
    await fs.mkdir(path.dirname(outputPath), { recursive: true });
    await fs.writeFile(outputPath, pem, { encoding: 'utf-8' });
    logger.info('Published CRL artifact', { outputPath });
    return outputPath;
  },

  /**
   * Read the published PEM encoded CRL for the active issuer.
   *
   * @param {string|undefined} [intermediateOverride] - Optional intermediate name to resolve against.
   * @returns {Promise<string>} PEM formatted CRL.
   */
  async getPublishedPemCrl(intermediateOverride = undefined) {
    const { issuerConfig } = getIssuerContext(intermediateOverride);
    const outputPath = path.join(config.getStoreDirectory(), issuerConfig.relativePath);
    try {
      return await fs.readFile(outputPath, 'utf-8');
    } catch (err) {
      if (err.code === 'ENOENT') {
        const notFound = new Error('Published CRL not found');
        notFound.code = 'ENOENT';
        throw notFound;
      }
      throw err;
    }
  },
};
