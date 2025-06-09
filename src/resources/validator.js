const jsonSchema = require('jsonschema');
const schemas = require('./schemas');

/**
 * Simple validation wrapper providing hostname and schema checks.
 */
module.exports = class Validator {
  #private = {};

  /**
   * Create a new Validator.
   *
   * @param {Object} configuration - Parsed configuration object.
   */
  constructor(configuration) {
    this.#private.config = configuration;
    this.#private.Validator = jsonSchema.Validator;
    this.#private.schemas = schemas;
  }

  /**
   * Validate that a hostname belongs to an allowed domain and has
   * at least three labels.
   *
   * @param {string} hostname - Hostname to verify.
   * @returns {boolean} True for valid hostnames.
   */
  hostname(hostname) {
    if (hostname.indexOf('.') < 0) {
      return false;
    }
    const hostnameParts = hostname.split('.');
    if (hostnameParts.length < 3) {
      return false;
    }
    if (this.#private.config.validDomains.indexOf(
      `${hostnameParts[hostnameParts.length - 2]}.${hostnameParts[hostnameParts.length - 1]}`,
    ) < 0) {
      return false;
    }
    return true;
  }

  /**
   * Validate a data object against one of the configured JSON schemas.
   *
   * @param {string} schemaName - Name of the schema to use.
   * @param {Object} data - Data object to validate.
   * @returns {boolean} True when data conforms to the schema.
   */
  validateSchema(schemaName, data) {
    const validator = new this.#private.Validator();
    const validationResults = validator.validate(data, this.#private.schemas[schemaName]);
    return validationResults.valid;
  }
};
