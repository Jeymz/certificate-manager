const jsonSchema = require('jsonschema');
const schemas = require('./schemas');

module.exports = class Validator {
  #private = {};

  constructor(configuration) {
    this.#private.config = configuration;
    this.#private.Validator = jsonSchema.Validator;
    this.#private.schemas = schemas;
  }

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

  validateSchema(schemaName, data) {
    const validator = new this.#private.Validator();
    const validationResults = validator.validate(data, this.#private.schemas[schemaName]);
    return validationResults.valid;
  }
};
