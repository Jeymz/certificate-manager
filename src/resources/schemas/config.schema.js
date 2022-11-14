module.exports = {
  id: '/config',
  type: 'object',
  additionalProperties: false,
  properties: {
    server: {
      type: 'object',
      additionalProperties: false,
      properties: {
        port: {
          type: 'number',
          minimum: 1,
          maximum: 65535,
          default: 80
        },
        sslPort: {
          type: 'number',
          minimum: 1,
          maximum: 65535,
          default: 443
        },
        ssl: {
          type: 'boolean',
          default: true
        }
      },
      required: [
        'port',
        'sslPort',
        'ssl'
      ]
    },
    ca: {
      type: 'object',
      additionalProperties: false,
      properties: {
        path: {
          type: 'string',
          minLength: 2,
          maxLength: 255,
          pattern: /^[a-zA-Z0-9_-\s.\\/:]+$/,
          default: './files'
        },
        validDomains: {
          type: 'array',
          items: {
            type: 'string',
            minLength: '4',
            pattern: /^[a-zA-Z0-9.-_]+$/
          }
        }
      },
      required: [
        'path'
      ]
    },
    certificate: {
      type: 'object',
      additionalProperties: false,
      properties: {
        email: {
          type: 'string',
          minLength: 6,
          maxLength: 255,
          pattern: /^[\w-.]+@([\w-]+.)+[\w-]{2,4}$/
        },
        organization: {
          type: 'string',
          minLength: 1,
          maxLength: 255,
          pattern: /^[\w-.\s]+$/
        },
        locality: {
          type: 'string',
          minLength: 1,
          maxLength: 45,
          pattern: /^[a-zA-Z\s]+$/
        },
        state: {
          type: 'string',
          minLength: 2,
          maxLength: 45,
          pattern: /^[a-zA-Z]+$/
        },
        country: {
          type: 'string',
          minLength: 2,
          maxLength: 2,
          pattern: /^[A-Z]{2}$/
        }
      },
      required: [
        'email',
        'organization',
        'locality',
        'state',
        'country'
      ]
    }
  },
  required: [
    'server',
    'ca',
    'certificate'
  ]
};
