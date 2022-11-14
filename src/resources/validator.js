const jsonSchema = require('jsonschema');
const schemas = require('./schemas/main');

class Validator {
  #private = {};

  constructor() {
    this.#private.Validator = jsonSchema.Validator;
    this.#private.schemas = schemas;
  }

  validateSchema(schemaName, data) {
    if (Object.keys(this.#private.schemas).indexOf(schemaName) < 0) {
      throw new Error('No matching schema found');
    }
    const validator = new this.#private.Validator();
    const validationResults = validator.validate(data, this.#private.schemas[schemaName]);
    console.log(validationResults);
    return validationResults.valid;
  }
}

const validator = new Validator();

module.exports = validator;
