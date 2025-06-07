const fs = require('fs');
const path = require('path');
const forge = require('node-forge');
const Validator = require('./validator');
const logger = require('../utils/logger');

const configurationFiles = {
  default: path.join(__dirname, '../', '../', 'config', 'defaults.json'),
};

let config = false;

// TODO: Move CA methods to their own class.
class Config {
  #private = {};

  constructor() {
    this.#private.configuration = JSON.parse(
      fs.readFileSync(configurationFiles.default, 'utf8'),
    );
    logger.debug(path.resolve('./files'));
    configurationFiles.storeDirectory = path.resolve(this.#private.configuration.storeDirectory);
    this.#private.subjectDefaults = [];
    Object.keys(this.#private.configuration.subject).forEach((key) => {
      this.#private.subjectDefaults.push({
        shortName: this.#private.configuration.subject[key].shortName,
        valueTagClass: forge.asn1.Type.UTF8,
        value: this.#private.configuration.subject[key].default,
      });
    });
    this.#private.storeDirectory = configurationFiles.storeDirectory;
    this.#private.validator = new Validator(this.#private.configuration);
    this.validateHostname = this.#private.validator.hostname;
    if (
      fs.existsSync(path.join(configurationFiles.storeDirectory, 'serial'))
      && fs.existsSync(path.join(configurationFiles.storeDirectory, 'certs'))
      && fs.existsSync(path.join(configurationFiles.storeDirectory, 'private'))
      && fs.existsSync(path.join(configurationFiles.storeDirectory, 'certs', 'ca.cert.crt'))
      && fs.existsSync(path.join(configurationFiles.storeDirectory, 'private', 'ca.key.pem'))
    ) {
      this.#private.initialized = true;
    } else {
      this.#private.initialized = false;
    }
  }

  getSubject() {
    return JSON.parse(JSON.stringify(this.#private.subjectDefaults));
  }

  getStoreDirectory() {
    return this.#private.storeDirectory;
  }

  getValidator() {
    return new Validator(this.#private.configuration);
  }

  isInitialized() {
    return this.#private.initialized;
  }

  getServerConfig() {
    return JSON.parse(JSON.stringify(this.#private.configuration.server));
  }

  getCertExtensions() {
    return JSON.parse(JSON.stringify(this.#private.configuration.extensions));
  }

}

module.exports = () => {
  if (!config) {
    config = new Config();
  }
  return config;
};
