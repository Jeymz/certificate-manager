module.exports = {
  id: '/cert',
  type: 'object',
  additionalProperties: false,
  properties: {
    hostname: {
      type: 'string',
      minLength: 6,
      maxLength: 255,
      pattern: /^[a-zA-Z0-9.-_]+$/
    },
    altNames: {
      type: 'array',
      items: {
        type: 'string',
        minLength: 4,
        maxLength: 255,
        pattern: /^[a-zA-Z0-9.-_]+$/
      }
    },
    passphrase: {
      type: 'string',
      minLength: 1,
      maxLength: 64
    }
  },
  required: [
    'hostname'
  ]
};
