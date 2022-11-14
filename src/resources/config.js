const path = require('path');
const fs = require('fs');
const os = require('os');
const validator = require('./validator');

const validEnvironments = [
  'local-dev',
  'development',
  'staging',
  'production',
  'test'
];

class Config {
  #private = {
    configDir: path.join(process.cwd(), 'config')
  };

  constructor() {
    // Set the environment
    if (!process.env?.NODE_ENV) {
      this.#private.environment = 'default';
    } else if (validEnvironments.indexOf(process.env.NODE_ENV.toLowerCase().trim()) < 0) {
      this.#private.environment = 'default';
    } else {
      this.#private.environment = process.env.NODE_ENV.toLowerCase().trim();
    }

    // Load configuration file check that it is valid json
    const configFile = path.join(this.#private.configDir, `${this.#private.environment}.json`);
    if (!fs.existsSync(configFile)) {
      throw new Error(`Unable to locate configuration - ${configFile}`);
    }
    this.#private.configText = fs.readFileSync(configFile, 'utf8');
    try {
      this.#private.config = JSON.parse(this.#private.configText);
    } catch (err) {
      console.log(err);
      throw new Error(`Invalid JSON provided in ${configFile}`);
    }

    // Perform configuration injections
    if (fs.existsSync(path.join(process.cwd(), 'config', 'requiredSecrets.json'))) {
      this.#injectSecrets();
    }
    this.#injectHelpers();

    // Validate configuration
    try {
      this.#private.config = JSON.parse(this.#private.configText);
    } catch (err) {
      console.log(err);
      throw new Error('Unable to parse JSON after injections');
    }

    if (!validator.validateSchema('config', this.#private.config)) {
      throw new Error('Invalid configuration provided');
    }
  }

  #injectSecrets() {
    try {
      const requiredSecrets = JSON.parse(
        fs.readFileSync(
          path.join(
            process.cwd(),
            'config',
            'requiredSecrets.json'
          ),
          'utf8'
        )
      );
      let providedSecrets = process.env;
      if (fs.existsSync(path.join(this.#private.configDir, `${this.#private.environment}.secrets.json`))) {
        providedSecrets = JSON.parse(
          fs.readFileSync(
            path.join(
              this.#private.configDir,
              `${this.#private.environment}.secrets.json`
            ),
            'utf8'
          )
        );
      }
      Object.keys(requiredSecrets).forEach((key) => {
        if (Object.keys(providedSecrets).indexOf(key) < 0) {
          throw new Error(`Missing ${key} secret`);
        }
        this.#private.configText = this.#private.configText.replaceAll(
          `{{${key}}}`,
          providedSecrets[key].toString()
        );
        if (Object.keys(process.env).indexOf(key) > -1) {
          delete process.env[key];
        }
      });
    } catch (err) {
      console.log(err);
      throw new Error('Unable to inject secrets');
    }
  }

  #injectHelpers() {
    this.#private.configText = this.#private.configText.replaceAll('{{CWD}}', process.cwd().toString().replaceAll('\\', '\\\\'));
    this.#private.configText = this.#private.configText.replaceAll('{{HOSTNAME}}', os.hostname().toString());
    this.#private.configText = this.#private.configText.replaceAll('{{DATETIME}}', new Date().getTime());
  }

  get(objectName) {
    if (Object.keys(this.#private.config).indexOf(objectName.toString()) < 0) {
      throw new Error('Invalid configuration object');
    }
    return JSON.parse(JSON.stringify(this.#private.config[objectName.toString()]));
  }

  getOnce(objectName) {
    if (Object.keys(this.#private.config).indexOf(objectName.toString()) < 0) {
      throw new Error('Invalid configuration object');
    }
    const configObject = JSON.parse(JSON.stringify(this.#private.config[objectName.toString()]));
    delete this.#private.config[objectName];
    return configObject;
  }
}

const config = new Config();

module.exports = config;
