const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const forge = require('node-forge');
const CertificateRequest = require('../resources/certificateRequest');
const CA = require('../resources/ca');
const revocation = require('../resources/revocation');
const config = require('../resources/config')();
const logger = require('../utils/logger');

async function writeP12ToFile(hostname, p12b64) {
  const store = config.getStoreDirectory();
  const bundlePath = path.join(store, 'newCerts', `${hostname}.bundle.p12`);
  await fs.writeFile(bundlePath, Buffer.from(p12b64, 'base64'), { mode: 0o600 });
  logger.info(`Saved PKCS#12 bundle: ${bundlePath}`);
  return bundlePath;
}

module.exports = {
  /**
   * Generate and sign a new web server certificate.
   *
   * @param {string} hostname - Fully qualified domain name for the certificate.
   * @param {string} passphrase - Passphrase to unlock the CA key.
   * @param {string[]|false} [altNames=false] - Optional alternative names.
   * @param {boolean} [bundleP12=false] - Whether to bundle as PKCS#12.
   * @param {string|null} [password=null] - Optional bundle password.
   * @returns {Promise<Object>} Resolves with certificate and key PEM strings.
   */
  async newWebServerCertificate(hostname, passphrase, altNames = false, bundleP12 = false, password = null, validityDays = null, performedBy = undefined) {
    const csr = new CertificateRequest(hostname);
    if (altNames && altNames.length > 0) {
      csr.addAltNames(altNames);
    }
    csr.sign();
    if (!csr.verify()) {
      return {
        error: 'Unable to verify CSR',
      };
    }
    if (!config.getDefaultIntermediate() && config.getRequireIntermediate()) {
      return { error: 'Root CA may not issue leaf certs' };
    }
    const ca = await new CA(config.getDefaultIntermediate());
    ca.unlockCA(passphrase, performedBy);
    const { certificate, serial, expiration, validityDaysApplied } = await ca.signCSR(csr, { validityDays });

    const store = config.getStoreDirectory();
    const certPath = path.join(store, 'newCerts', `${hostname}.cert.crt`);
    const csrPath = path.join(store, 'requests', `${hostname}.request.pem`);
    const privateKeyPath = path.join(store, 'private', `${hostname}.key.pem`);
    await fs.writeFile(certPath, certificate, { encoding: 'utf-8' });
    if (config.getDefaultIntermediate()) {
      const chainPem = `${certificate}${ca.getCACertificate()}`;
      await fs.writeFile(path.join(store, 'newCerts', `${hostname}.chain.crt`), chainPem, { encoding: 'utf-8' });
    }
    await fs.writeFile(csrPath, csr.getCSR(), { encoding: 'utf-8' });
    const privateKey = csr.getPrivateKey();
    await fs.writeFile(privateKeyPath, privateKey, { encoding: 'utf-8' });

    await revocation.add(serial, hostname, expiration.toISOString());
    await ca.updateLog(csrPath, certPath, privateKeyPath, expiration, hostname, validityDaysApplied);

    const caChain = ca.getCertChain();
    const chain = `${certificate}${caChain}`;
    const result = {
      certificate,
      privateKey,
      hostname,
      chain,
    };
    if (bundleP12) {
      const bundlePass = password || passphrase;
      result.p12 = csr.getPkcs12Bundle(certificate, caChain, bundlePass);
      await writeP12ToFile(hostname, result.p12);
    }
    logger.audit.info({
      timestamp: new Date().toISOString(),
      eventType: 'CERT_ISSUE',
      subject: hostname,
      serialNumber: serial.toString(),
      performedBy,
      validityDaysRequested: validityDays,
      validityDaysApplied,
    });
    return result;
  },

  /**
   * Generate and sign a new LDAP server certificate.
   *
   * @param {string} hostname - Fully qualified domain name for the certificate.
   * @param {string} passphrase - Passphrase to unlock the CA key.
   * @param {string[]|false} [altNames=false] - Optional alternative names.
   * @param {boolean} [bundleP12=false] - Whether to bundle as PKCS#12.
   * @param {string|null} [password=null] - Optional bundle password.
   * @returns {Promise<Object>} Resolves with certificate and key PEM strings.
   */
  async newLdapServerCertificate(hostname, passphrase, altNames = false, bundleP12 = false, password = null, validityDays = null, performedBy = undefined) {
    const csr = new CertificateRequest(hostname);
    csr.setCertType('ldapServer');
    if (altNames && altNames.length > 0) {
      csr.addAltNames(altNames);
    }
    csr.sign();
    if (!csr.verify()) {
      return {
        error: 'Unable to verify CSR',
      };
    }
    if (!config.getDefaultIntermediate() && config.getRequireIntermediate()) {
      return { error: 'Root CA may not issue leaf certs' };
    }
    const ca = await new CA(config.getDefaultIntermediate());
    ca.unlockCA(passphrase, performedBy);
    const { certificate, serial, expiration, validityDaysApplied } = await ca.signCSR(csr, { validityDays });

    const store = config.getStoreDirectory();
    const certPath = path.join(store, 'newCerts', `${hostname}.cert.crt`);
    const csrPath = path.join(store, 'requests', `${hostname}.request.pem`);
    const privateKeyPath = path.join(store, 'private', `${hostname}.key.pem`);
    await fs.writeFile(certPath, certificate, { encoding: 'utf-8' });
    if (config.getDefaultIntermediate()) {
      const chainPem = `${certificate}${ca.getCACertificate()}`;
      await fs.writeFile(path.join(store, 'newCerts', `${hostname}.chain.crt`), chainPem, { encoding: 'utf-8' });
    }
    await fs.writeFile(csrPath, csr.getCSR(), { encoding: 'utf-8' });
    const privateKey = csr.getPrivateKey();
    await fs.writeFile(privateKeyPath, privateKey, { encoding: 'utf-8' });

    await revocation.add(serial, hostname, expiration.toISOString());
    await ca.updateLog(csrPath, certPath, privateKeyPath, expiration, hostname, validityDaysApplied);

    const caChain = ca.getCertChain();
    const chain = `${certificate}${caChain}`;
    const result = {
      certificate,
      privateKey,
      hostname,
      chain,
    };
    if (bundleP12) {
      const bundlePass = password || passphrase;
      result.p12 = csr.getPkcs12Bundle(certificate, caChain, bundlePass);
      await writeP12ToFile(hostname, result.p12);
    }
    logger.audit.info({
      timestamp: new Date().toISOString(),
      eventType: 'CERT_ISSUE',
      subject: hostname,
      serialNumber: serial.toString(),
      performedBy,
      validityDaysRequested: validityDays,
      validityDaysApplied,
    });
    return result;
  },

  /**
   * Renew an existing certificate using stored subject and SAN data.
   *
   * @param {string} serialNumber - Serial number of the certificate to renew.
   * @param {string} passphrase - Passphrase to unlock the CA.
   * @param {boolean} [bundleP12=false] - Whether to bundle as PKCS#12.
   * @param {string|null} [password=null] - Optional bundle password.
   * @returns {Promise<Object>} Resolves with renewed certificate and key material.
   */
  async renewCertificate(serialNumber, passphrase, bundleP12 = false, password = null, validityDays = null, performedBy = undefined) {
    const existing = await revocation.getBySerial(serialNumber);
    if (!existing) {
      return { error: 'Serial not found' };
    }
    if (existing.revoked) {
      return { error: 'Certificate is revoked' };
    }

    const limits = (config.getValidityLimits && config.getValidityLimits()) || { minDays: 1, maxDays: 397 };
    let finalValidity = validityDays;
    if (finalValidity !== null && (finalValidity < limits.minDays || finalValidity > limits.maxDays)) {
      return { error: `validityDays must be between ${limits.minDays} and ${limits.maxDays}` };
    }

    const store = config.getStoreDirectory();
    const certPath = path.join(store, 'newCerts', `${existing.hostname}.cert.crt`);
    const csrPath = path.join(store, 'requests', `${existing.hostname}.request.pem`);
    const privateKeyPath = path.join(store, 'private', `${existing.hostname}.key.pem`);

    let certPem;
    let privateKey;
    try {
      [certPem, privateKey] = await Promise.all([
        fs.readFile(certPath, 'utf-8'),
        fs.readFile(privateKeyPath, 'utf-8'),
      ]);
    } catch (err) {
      logger.error(`Unable to load existing certificate material for ${existing.hostname}: ${err.message}`);
      return { error: 'Original certificate material not found' };
    }

    const cert = forge.pki.certificateFromPem(certPem);
    const cnField = (typeof cert.subject.getField === 'function')
      ? cert.subject.getField('CN')
      : (cert.subject.attributes || []).find((attr) => attr.shortName === 'CN');
    if (!cnField || !cnField.value) {
      return { error: 'Certificate subject is missing a common name' };
    }
    const hostname = cnField.value.toString().toLowerCase();

    const sanExtension = (cert.extensions || []).find((ext) => ext.name === 'subjectAltName');
    const altNames = [];
    if (sanExtension && Array.isArray(sanExtension.altNames)) {
      sanExtension.altNames.forEach((alt) => {
        if (alt.type === 7 && alt.ip) {
          altNames.push(alt.ip);
        } else if (alt.type === 2 && alt.value) {
          altNames.push(alt.value);
        }
      });
    }

    const extKeyUsage = (cert.extensions || []).find((ext) => ext.name === 'extKeyUsage');
    const certType = extKeyUsage?.clientAuth ? 'ldapServer' : 'webServer';
    if (finalValidity === null) {
      const profileDefault = (config.getProfileValidity && config.getProfileValidity(certType)) || null;
      if (profileDefault) {
        if (profileDefault < limits.minDays || profileDefault > limits.maxDays) {
          return { error: 'Invalid server configuration for profile validity' };
        }
        finalValidity = profileDefault;
      }
    }

    const csr = new CertificateRequest(
      hostname,
      {
        publicKey: forge.pki.publicKeyToPem(cert.publicKey),
        privateKeyPEM: privateKey,
      },
    );
    if (certType !== 'webServer') {
      csr.setCertType(certType);
    }
    if (altNames.length > 0) {
      csr.addAltNames(altNames);
    }
    csr.sign();
    if (!csr.verify()) {
      return {
        error: 'Unable to verify CSR',
      };
    }
    if (!config.getDefaultIntermediate() && config.getRequireIntermediate()) {
      return { error: 'Root CA may not issue leaf certs' };
    }
    const ca = await new CA(config.getDefaultIntermediate());
    ca.unlockCA(passphrase, performedBy);
    const { certificate, serial, expiration, validityDaysApplied } = await ca.signCSR(csr, { validityDays: finalValidity });

    await fs.writeFile(certPath, certificate, { encoding: 'utf-8' });
    if (config.getDefaultIntermediate()) {
      const chainPem = `${certificate}${ca.getCACertificate()}`;
      await fs.writeFile(path.join(store, 'newCerts', `${hostname}.chain.crt`), chainPem, { encoding: 'utf-8' });
    }
    await fs.writeFile(csrPath, csr.getCSR(), { encoding: 'utf-8' });

    await revocation.add(serial, hostname, expiration.toISOString());
    await ca.updateLog(csrPath, certPath, privateKeyPath, expiration, hostname, validityDaysApplied);

    const caChain = ca.getCertChain();
    const chain = `${certificate}${caChain}`;
    const result = {
      certificate,
      privateKey,
      hostname,
      chain,
    };
    if (bundleP12) {
      const bundlePass = password || passphrase;
      result.p12 = csr.getPkcs12Bundle(certificate, caChain, bundlePass);
      await writeP12ToFile(hostname, result.p12);
    }
    logger.audit.info({
      timestamp: new Date().toISOString(),
      eventType: 'CERT_RENEW',
      subject: hostname,
      serialNumber: serial.toString(),
      renewedFromSerial: serialNumber.toString(),
      performedBy,
      validityDaysRequested: validityDays,
      validityDaysApplied,
    });
    return result;
  },

  /**
   * Generate and sign a new intermediate CA certificate.
   *
   * @param {string} hostname - Name for the intermediate CA.
   * @param {string} passphrase - Passphrase to unlock the root CA key.
   * @param {string} [intermediatePassphrase] - Passphrase for the new CA key.
   * @returns {Promise<Object>} Resolves with certificate and key PEM strings.
   */
  async newIntermediateCA(hostname, passphrase, intermediatePassphrase, performedBy = undefined) {
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

    const csr = new CertificateRequest(hostname, {
      publicKey: keypair.publicKey,
      privateKeyPEM: keypair.privateKey,
      passphrase: intermediatePassphrase,
    });
    csr.setCertType('intermediateCA');
    csr.sign();
    if (!csr.verify()) {
      return { error: 'Unable to verify CSR' };
    }
    const ca = await new CA();
    ca.unlockCA(passphrase, performedBy);
    const { certificate, serial } = await ca.signCSR(csr);
    const privateKey = keypair.privateKey;
    const intDir = path.join(config.getStoreDirectory(), 'intermediates');
    await fs.mkdir(intDir, { recursive: true });
    await fs.writeFile(path.join(intDir, `${hostname}.cert.crt`), certificate, { encoding: 'utf-8' });
    await fs.writeFile(path.join(intDir, `${hostname}.key.pem`), privateKey, { encoding: 'utf-8' });
    logger.audit.info({
      timestamp: new Date().toISOString(),
      eventType: 'CA_CREATE',
      subject: hostname,
      serialNumber: serial.toString(),
      performedBy,
    });
    return { certificate, privateKey, hostname };
  },
};
