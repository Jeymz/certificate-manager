const fs = require('fs').promises;
const path = require('path');
const forge = require('node-forge');
const config = require('./config')();
const logger = require('../utils/logger');

/**
 * Certificate Authority helper for issuing and tracking certificates.
 */
module.exports = class CA {
  #private = {};

  /**
   * Create a new CA instance and asynchronously load key material.
   *
   * @returns {Promise<CA>} Resolves when initialization completes.
   */
  constructor(intermediate = null) {
    const storeDirectory = config.getStoreDirectory();
    this.#private.store = {
      certs: path.join(storeDirectory, 'newCerts'),
      requests: path.join(storeDirectory, 'requests'),
      root: storeDirectory,
      log: path.join(storeDirectory, 'log.json'),
      intermediate,
    };
    return (async() => {
      this.#private.serial = await fs.readFile(
        path.join(this.#private.store.root, 'serial'),
        'utf-8',
      );
      if (intermediate) {
        const base = path.join(this.#private.store.root, 'intermediates');
        this.#private.caCert = await fs.readFile(
          path.join(base, `${intermediate}.cert.crt`),
          'utf-8',
        );
        this.#private.lockedKey = await fs.readFile(
          path.join(base, `${intermediate}.key.pem`),
          'utf-8',
        );
      } else {
        this.#private.caCert = await fs.readFile(
          path.join(this.#private.store.root, 'certs', 'ca.cert.crt'),
          'utf-8',
        );
        this.#private.lockedKey = await fs.readFile(
          path.join(this.#private.store.root, 'private', 'ca.key.pem'),
          'utf-8',
        );
      }
      return this;
    })();
  }

  /**
   * Increment and persist the CA serial number.
   *
   * @returns {Promise<string>} Resolves to the new serial number as a string.
   */
  async getSerial() {
    this.#private.serial = (parseInt(this.#private.serial, 10) + 1).toString();
    await fs.writeFile(
      path.join(this.#private.store.root, 'serial'),
      this.#private.serial,
      'utf-8',
    );
    return this.#private.serial.toString();
  }

  /**
   * Decrypt the CA private key using the provided passphrase.
   *
   * @param {string} passphrase - Passphrase used to decrypt the key.
   * @returns {void}
   */
  unlockCA(passphrase) {
    this.#private.caKey = forge.pki.decryptRsaPrivateKey(this.#private.lockedKey, passphrase);
  }

  /**
   * Retrieve the PEM encoded certificate used for signing.
   *
   * @returns {string} Signing CA certificate in PEM format.
   */
  getCACertificate() {
    return this.#private.caCert;
  }

  /**
   * Sign a certificate signing request.
   *
   * @param {import('./certificateRequest')} CSR - Certificate request instance.
   * @returns {Promise<string>} Resolves to the PEM encoded certificate.
   * @throws {Error} If the CA key is locked or the CSR is invalid.
   */
  async signCSR(CSR) {
    if (!this.#private.caKey) {
      throw new Error(`CA key is locked; unable to sign certificate for ${CSR.getHostname()}`);
    }
    const csr = forge.pki.certificationRequestFromPem(CSR.getCSR());
    const caCert = forge.pki.certificateFromPem(this.#private.caCert);
    const { caKey } = this.#private;
    if (!csr.verify()) {
      throw new Error(`CSR verification failed for ${CSR.getHostname()}`);
    }
    const newCert = forge.pki.createCertificate();
    const serial = await this.getSerial();
    newCert.serialNumber = parseInt(serial, 10).toString(16);
    const certFilename = `${CSR.getHostname()}.cert.crt`;
    const requestFilename = `${CSR.getHostname()}.request.pem`;
    const privateKeyFilename = `${CSR.getHostname()}.key.pem`;
    const expiration = new Date();
    expiration.setFullYear(expiration.getFullYear() + 1);
    const certPath = path.join(this.#private.store.certs, certFilename);
    const csrPath = path.join(this.#private.store.requests, requestFilename);
    const privateKeyPath = path.join(this.#private.store.root, 'private', privateKeyFilename);
    newCert.validity.notBefore = new Date();
    newCert.validity.notAfter = expiration;
    newCert.setSubject(csr.subject.attributes);
    const extensionConfigs = config.getCertExtensions();
    const extensions = extensionConfigs[CSR.getCertType()];
    if (csr.attributes.length === 3) {
      if (csr.attributes[csr.attributes.length - 1].name === 'extensionRequest') {
        csr.attributes[csr.attributes.length - 1].extensions.forEach((extensionRequest) => {
          if (extensionRequest.name === 'subjectAltName') {
            extensions.push(extensionRequest);
          }
        });
      }
    }
    newCert.setIssuer(caCert.subject.attributes);
    newCert.publicKey = csr.publicKey;
    logger.debug(extensions);
    newCert.setExtensions(extensions);
    newCert.sign(caKey, forge.md.sha256.create());
    const certPem = forge.pki.certificateToPem(newCert);
    await fs.writeFile(
      certPath,
      certPem,
      { encoding: 'utf-8' },
    );
    if (this.#private.store.intermediate) {
      const chainPath = path.join(
        this.#private.store.certs,
        `${CSR.getHostname()}.chain.crt`,
      );
      const chainPem = `${certPem}${this.#private.caCert}`;
      await fs.writeFile(chainPath, chainPem, { encoding: 'utf-8' });
    }
    await fs.writeFile(
      csrPath,
      CSR.getCSR(),
      { encoding: 'utf-8' },
    );
    await fs.writeFile(
      privateKeyPath,
      CSR.getPrivateKey(),
      { encoding: 'utf-8' },
    );
    await this.updateLog(csrPath, certPath, privateKeyPath, expiration, CSR.getHostname());
    return forge.pki.certificateToPem(newCert);
  }

  /**
   * Append request details to the certificate issuance log.
   *
   * @param {string} csrPath - Path to the stored CSR.
   * @param {string} certPath - Path to the issued certificate.
   * @param {string} privateKeyPath - Path to the generated private key.
   * @param {Date} expiration - Expiration date of the certificate.
   * @param {string} hostname - Hostname the certificate was issued for.
   * @returns {Promise<void>}
   */
  async updateLog(csrPath, certPath, privateKeyPath, expiration, hostname) {
    const log = JSON.parse(await fs.readFile(
      this.#private.store.log,
      { encoding: 'utf-8' },
    ));
    log.requests.push({
      request: csrPath,
      certificate: certPath,
      privateKey: privateKeyPath,
      expiration,
      hostname,
    });
    await fs.writeFile(
      this.#private.store.log,
      JSON.stringify(log),
      { encoding: 'utf-8' },
    );
  }
};
