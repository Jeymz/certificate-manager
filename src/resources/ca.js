const fs = require('fs');
const path = require('path');
const forge = require('node-forge');
const config = require('./config')();
const logger = require('../utils/logger');

module.exports = class CA {
  #private = {};

  constructor() {
    const storeDirectory = config.getStoreDirectory();
    this.#private.store = {
      certs: path.join(storeDirectory, 'newCerts'),
      requests: path.join(storeDirectory, 'requests'),
      root: storeDirectory,
      log: path.join(storeDirectory, 'log.json'),
    };
    this.#private.serial = fs.readFileSync(
      path.join(this.#private.store.root, 'serial'),
      'utf-8',
    );
    this.#private.caCert = fs.readFileSync(
      path.join(this.#private.store.root, 'certs', 'ca.cert.crt'),
      'utf-8',
    );
    this.#private.lockedKey = fs.readFileSync(
      path.join(this.#private.store.root, 'private', 'ca.key.pem'),
      'utf-8',
    );
  }

  getSerial() {
    this.#private.serial = (parseInt(this.#private.serial, 10) + 1).toString();
    fs.writeFileSync(
      path.join(this.#private.store.root, 'serial'),
      this.#private.serial,
      'utf-8',
    );
    return this.#private.serial.toString();
  }

  unlockCA(passphrase) {
    this.#private.caKey = forge.pki.decryptRsaPrivateKey(this.#private.lockedKey, passphrase);
  }

  signCSR(CSR) {
    if (!this.#private.caKey) {
      throw new Error('CA Key is locked');
    }
    const csr = forge.pki.certificationRequestFromPem(CSR.getCSR());
    const caCert = forge.pki.certificateFromPem(this.#private.caCert);
    const { caKey } = this.#private;
    if (!csr.verify()) {
      throw new Error('Invalid CSR');
    }
    const newCert = forge.pki.createCertificate();
    newCert.serialNumber = this.getSerial();
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
    logger.debug(extensions);
    newCert.setExtensions(extensions);

    newCert.publicKey = csr.publicKey;
    newCert.sign(caKey, forge.md.sha256.create());
    fs.writeFileSync(
      certPath,
      forge.pki.certificateToPem(newCert),
      { encoding: 'utf-8' },
    );
    fs.writeFileSync(
      csrPath,
      CSR.getCSR(),
      { encoding: 'utf-8' },
    );
    fs.writeFileSync(
      privateKeyPath,
      CSR.getPrivateKey(),
      { encoding: 'utf-8' },
    );
    this.updateLog(csrPath, certPath, privateKeyPath, expiration, CSR.getHostname());
    return forge.pki.certificateToPem(newCert);
  }

  updateLog(csrPath, certPath, privateKeyPath, expiration, hostname) {
    const log = JSON.parse(fs.readFileSync(
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
    fs.writeFileSync(
      this.#private.store.log,
      JSON.stringify(log),
      { encoding: 'utf-8' },
    );
  }
};
