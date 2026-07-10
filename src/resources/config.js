const fs = require('fs');
const path = require('path');
const forge = require('node-forge');
const Validator = require('./validator');
const logger = require('../utils/logger');

const configurationFiles = {
  default: process.env.CONFIG_PATH
    ? path.resolve(process.env.CONFIG_PATH)
    : path.join(__dirname, '../', '../', 'config', 'defaults.json'),
};

let config = false;


/**
 * Configuration management and validation helper.
 */
class Config {
  #private = {};

  /**
   * Initialize configuration from defaults and check file system state.
   */
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
    this.#private.defaultIntermediate =
      this.#private.configuration.defaultIntermediate || null;
    this.#private.requireIntermediate =
      this.#private.configuration.requireIntermediate !== undefined
        ? this.#private.configuration.requireIntermediate
        : true;
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

  /**
   * Retrieve a copy of the default certificate subject attributes.
   *
   * @returns {Object[]} Array of subject attribute objects.
   */
  getSubject() {
    return JSON.parse(JSON.stringify(this.#private.subjectDefaults));
  }

  /**
   * Get the absolute path of the certificate store directory.
   *
   * @returns {string} Directory path used to persist certificates.
   */
  getStoreDirectory() {
    return this.#private.storeDirectory;
  }

  /**
   * Create a new Validator instance using the loaded configuration.
   *
   * @returns {import('./validator')} Validator for input checking.
   */
  getValidator() {
    return new Validator(this.#private.configuration);
  }

  /**
   * Determine if the certificate store appears to be initialized.
   *
   * @returns {boolean} True when required CA files exist.
   */
  isInitialized() {
    return this.#private.initialized;
  }

  /**
   * Provide server configuration settings from the defaults file.
   *
   * @returns {Object} Configuration for the web server.
   */
  getServerConfig() {
    return JSON.parse(JSON.stringify(this.#private.configuration.server));
  }

  /**
   * Retrieve revocation publication settings.
   *
   * @returns {{enabled:boolean, issuers:Object<string, {publicUrl:string, relativePath:string}>}}
   * Revocation publication configuration.
   */
  getRevocationPublishing() {
    const revocationPublishing = this.#private.configuration.revocationPublishing || {};
    return {
      enabled: revocationPublishing.enabled === true,
      issuers: JSON.parse(JSON.stringify(revocationPublishing.issuers || {})),
    };
  }

  /**
   * Retrieve revocation publication settings for a named issuer key.
   *
   * @param {string} issuerKey - Logical issuer key such as `root` or `defaultIntermediate`.
   * @returns {{publicUrl:string, relativePath:string}|null} Issuer publication settings or null.
   */
  getRevocationIssuerConfig(issuerKey) {
    const revocationPublishing = this.getRevocationPublishing();
    if (!issuerKey || !revocationPublishing.issuers[issuerKey]) {
      return null;
    }
    return JSON.parse(JSON.stringify(revocationPublishing.issuers[issuerKey]));
  }

  /**
   * Determine which issuer profile is currently active for CRL publication.
   *
   * @returns {"root"|"defaultIntermediate"} Active issuer configuration key.
   */
  getActiveRevocationIssuerKey() {
    return this.#private.defaultIntermediate ? 'defaultIntermediate' : 'root';
  }

  /**
   * Retrieve publication settings for the currently active issuer.
   *
   * @returns {{publicUrl:string, relativePath:string}|null} Active issuer publication settings.
   */
  getActiveRevocationIssuerConfig() {
    return this.getRevocationIssuerConfig(this.getActiveRevocationIssuerKey());
  }

  /**
   * Retrieve configured X.509 extension profiles.
   *
   * @returns {Object.<string,Array>} Mapping of extension sets by name.
   */
  getCertExtensions() {
    return JSON.parse(JSON.stringify(this.#private.configuration.extensions));
  }

  /**
   * Retrieve global validity limits (days).
   * @returns {{minDays:number,maxDays:number}}
   */
  getValidityLimits() {
    const limits = this.#private.configuration.validityLimits || {};
    return {
      minDays: limits.minDays || 1,
      maxDays: limits.maxDays || 397,
    };
  }

  /**
   * Retrieve configured default validityDays for a profile if present.
   * @param {string} profile
   * @returns {number|null}
   */
  getProfileValidity(profile) {
    if (Object.keys(this.#private.configuration?.extensions).indexOf(profile) < 0) {
      return null;
    }
    // allow optional metadata object on profile called _meta.validityDays
    if (this.#private.configuration.profileMetadata && this.#private.configuration.profileMetadata[profile] && this.#private.configuration.profileMetadata[profile].validityDays) {
      return this.#private.configuration.profileMetadata[profile].validityDays;
    }
    return null;
  }

  getDefaultIntermediate() {
    return this.#private.defaultIntermediate;
  }

  getRequireIntermediate() {
    return this.#private.requireIntermediate;
  }
}

/**
 * Singleton factory for the Config instance.
 *
 * @returns {Config} Configured instance reused across imports.
 */
module.exports = () => {
  if (!config) {
    config = new Config();
  }
  return config;
};
