const crypto = require('crypto');
const forge = require('node-forge');
const net = require('net');
const config = require('./config')();

module.exports = class request {
  #private = {};

  constructor(hostname) {
    const keypair = forge.pki.rsa.generateKeyPair(2048);
    this.#private.keypair = {
      publicKey: forge.pki.publicKeyToPem(keypair.publicKey),
      privateKey: keypair.privateKey
    };
    this.#private.csr = forge.pki.createCertificationRequest();
    this.#private.csr.publicKey = forge.pki.publicKeyFromPem(this.#private.keypair.publicKey);
    const subject = config.getSubject();
    this.#private.validator = config.getValidator();
    const normalized = hostname.toString().toLowerCase();
    if (!this.#private.validator.hostname(normalized)) {
      throw new Error('Invalid hostname');
    }
    subject.push({
      shortName: 'CN',
      value: normalized
    });
    this.#private.csr.setSubject(subject);
    this.#private.attributes = [
      {
        name: 'challengePassword',
        value: crypto.randomBytes(32).toString('base64')
      },
      {
        name: 'unstructuredName',
        value: 'Robotti Tech Services'
      }
    ];
    this.#private.hostname = normalized;
    this.#private.certType = 'webServer';
  }

  addAltNames(altNames) {
    const subjectAltName = {
      name: 'subjectAltName',
      altNames: []
    };
    altNames.forEach((alternateName) => {
      const normalized = alternateName.toString().toLowerCase();
      if (net.isIP(normalized)) {
        subjectAltName.altNames.push({
          type: 7,
          ip: normalized
        });
      } else if (this.#private.validator.hostname(normalized)) {
        subjectAltName.altNames.push({
          type: 2,
          value: normalized
        });
      }
    });
    if (subjectAltName.altNames.length > 0) {
      this.#private.attributes.push({
        name: 'extensionRequest',
        extensions: [
          subjectAltName
        ]
      });
    }
  }

  sign() {
    this.#private.csr.setAttributes(this.#private.attributes);
    this.#private.csr.sign(this.#private.keypair.privateKey);
    this.#private.csrPEM = forge.pki.certificationRequestToPem(this.#private.csr);
  }

  verify() {
    return this.#private.csr.verify();
  }

  getHostname() {
    return this.#private.hostname;
  }

  getCSR() {
    return this.#private.csrPEM;
  }

  getPrivateKey() {
    return forge.pki.privateKeyToPem(this.#private.keypair.privateKey);
  }

  setCertType(certType) {
    const certConfigs = config.getCertExtensions();
    if (Object.keys(certConfigs).indexOf(certType.toString()) < 0) {
      throw new Error('Invalid or unsupported cert type provided');
    } else {
      this.#private.certType = certType.toString();
    }
  }

  getCertType() {
    return this.#private.certType;
  }
};
