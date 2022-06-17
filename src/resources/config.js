const path = require('path');
const fs = require('fs');
const Validator = require('./validator');

const configurationFiles = {
  default: path.join(__dirname, '../', '../', 'config', 'defaults.json'),
  storeDirectory: path.join(__dirname, '../', '../', 'files')
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
    this.#private.storeDirectory = configurationFiles.storeDirectory;
    this.#private.validator = new Validator(this.#private.configuration.validationConfig);
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
    return this.#private.subjectDefaults;
  }

  getStoreDirectory() {
    return this.#private.storeDirectory;
  }

  getValidator() {
    return new Validator(this.#private.configuration.validationConfig);
  }

  isInitialized() {
    return this.#private.initialized;
  }

  getServerConfig() {
    return this.#private.configuration.server;
  }
}

module.exports = () => {
  if (!config) {
    config = new Config();
  }
  return config;
};
