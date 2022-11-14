const forge = require('node-forge');
const crypto = require('crypto');
const config = require('./config');
const validator = require('./validator');

class Certificate {
  #private = {};

  constructor(request) {
    const keypair = forge.pki.rsa.generateKeyPair(2048);
    this.#private.keypair = {
      publicKey: forge.pki.publicKeyToPem(keypair.publicKey),
      privateKey: keypair.privateKey
    };
    this.#private.request = request;
    if (!validator.validateSchema('cert', this.#private.request)) {
      throw new Error('Invalid certificate request data');
    }
    this.#private.subject = config.get('certificate');
    this.#private.subject.push({
      shortName: 'CN',
      value: this.#private.request.hostname.toLowerCase()
    });
    this.#private.attributes = [{
      name: 'challengePassword',
      value: crypto.randomBytes(32).toString('base64')
    }];
    if (this.#private.request?.altNames && this.#private.request.altNames.length > 0) {
      this.#addAlternateNames();
    }
  }

  #addAlternateNames() {
    const subjectAltName = {
      name: 'subjectAltName',
      altNames: []
    };
    this.#private.request.altNames.forEach((alternateName) => {
      subjectAltName.altNames.push({
        type: 2,
        value: alternateName
      });
    });
    this.#private.attributes.push({
      name: 'extensionRequest',
      extensions: [
        subjectAltName
      ]
    });
  }
}

module.exports = Certificate;
