module.exports = {
  new: {
    id: '/new',
    type: 'object',
    additionalProperties: false,
    properties: {
      hostname: {
        type: 'string',
        pattern: /^[a-zA-Z0-9._-]+$/,
        minLength: 6,
      },
      altNames: {
        type: 'array',
        items: {
          type: 'string',
          minLength: 1,
          pattern: /^[a-zA-Z0-9.:_-]+$/,
        },
      },
      passphrase: {
        type: 'string',
        minLength: 1,
      },
      bundleP12: {
        type: 'boolean',
      },
      password: {
        type: 'string',
        minLength: 4,
        maxLength: 128,
      },
    },
    required: [
      'hostname',
      'passphrase',
    ],
  },
  intermediate: {
    id: '/intermediate',
    type: 'object',
    additionalProperties: false,
    properties: {
      hostname: {
        type: 'string',
        pattern: /^[a-zA-Z0-9._-]+$/,
        minLength: 6,
      },
      passphrase: {
        type: 'string',
        minLength: 1,
      },
      intermediatePassphrase: {
        type: 'string',
        minLength: 1,
      },
    },
    required: [
      'hostname',
      'passphrase',
      'intermediatePassphrase',
    ],
  },
  revoke: {
    id: '/revoke',
    type: 'object',
    additionalProperties: false,
    properties: {
      serialNumber: {
        type: 'string',
        pattern: /^\d+$/,
      },
      reason: {
        type: 'string',
      },
    },
    required: ['serialNumber'],
  },
};
