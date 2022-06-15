const path = require('path');
const fs = require('fs');
const forge = require('forge');

const configurationFiles = {
  default: path.join('../', '../', 'config', 'defaults.json'),
  files: path.join('../', '../', 'files')
};

let config = false;

// TODO: Move CA methods to their own class.
class Config {
  #private = {};

  constructor() {
    this.#private.configuration = JSON.parse(
      fs.readFileSync(configurationFiles.default, 'utf8')
    );
    this.#private.subjectDefaults = [];
    Object.keys(this.#private.configuration.subject).forEach((key) => {
      this.#private.subjectDefaults.push({
        shortName: this.#private.configuration.subject[key].shortName,
        value: this.#private.configuration.subject[key].default
      });
    });
    this.#private.caKey = fs.readFileSync(
      path.join(configurationFiles.files, 'private', 'ca.key.pem'),
      'utf-8'
    );
    this.#private.caCert = fs.readFileSync(
      path.join(configurationFiles.files, 'certs', 'ca.cert.pem'),
      'utf-8'
    )
    this.#private.serial = fs.readFileSync(
      path.join(configurationFiles.files, 'serial'),
      'utf-8'
    )
    this.#private.serial = parseInt(this.#private.serial, 10);
  }

  #increaseSerial() {
    this.#private.serial += 1;
    fs.writeFileSync(
      path.join(configurationFiles.files, 'serial'),
      this.#private.serial.toString(),
      'utf-8'
    );
    return this.#private.serial;
  }
  
  storeCAPassphrase(passphrase) {
    this.#private.caPassphrase = passphrase;
  }

  signCSR(csrCert) {
    try {
      const csr = forge.pki.certificationRequestFromPem;
      if (!this.#private.caPassphrase) {
        return { error: 'CA is locked' };
      }
      const caCert = forge.pki.certificateFromPem(this.#private.caCert);
      const caKey = forge.pki.decryptRsaPrivateKey(
        this.#private.caKey,
        this.#private.passphrase
      );
      if (!csr.verify()) {
        return { error: 'Invalid signature' }
      }
      const certificate = forge.pki.createCertificate();
      certificate.serialNumber = this.#increaseSerial();
      certificate.validity.notBefore = new Date();
      certificate.validity.notAfter = new Date();
      certificate.validity.notAfter.setFullYear(
        certificate.validity.notBefore.getFullYear() + 1
      );
      certificate.setSubject(csr.subject.attributes);
      certificate.setIssuer(caCert.subject.attributes);
    } catch (err) {
      return {
        error: 'Unable to sign'
      }
    }
  }

  getSubject() {
    return this.#private.subjectDefaults;
  }
  
  validateHostname(hostname) {
    if (typeof hostname !== 'string' || hostname.indexOf('.') < 0) {
      return {
        valid: false,
        reason: 'Invalid hostname provided'
      };
    }
    const hostnameParts = hostname.split('.');
    if (hostnameParts.length < 3) {
      return {
        valid: false,
        reason: 'Invalid hostname provided'
      }
    }
    const length = hostnameParts.length;
    const domainName = `${hostnameParts[length - 2]}.${hostnameParts[length - 1]}`;
    if (this.#private.configuration.validDomains.indexOf(domainName) < 0) {
      return {
        valid: false,
        reason: 'Hostname does not contain a valid domain name for this CA'
      };
    }
    return {
      valid: true,
      subject: {
        shortName: 'CN',
        value: hostname.toString().toLowerCase()
      }
    }
  }
}

module.exports = () => {
  if (!config) {
    config = new Config();
  }
  return config;
}