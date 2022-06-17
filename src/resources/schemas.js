module.exports = {
  new: {
    id: '/new',
    type: 'object',
    additionalProperties: false,
    properties: {
      hostname: {
        type: 'string',
        minLength: 6
      },
      altNames: {
        type: 'array',
        items: {
          type: 'string',
          minLength: '1',
          pattern: /^[a-zA-Z0-9.-_]+$/
        }
      },
      passphrase: {
        type: 'string',
        minLength: 1
      }
    },
    required: [
      'hostname',
      'passphrase'
    ]
  }
};
