const https = require('https');
const jwksClient = require('jwks-rsa');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
// const { logger } = require('./logger');
// const db = require('./db');
const config = require('../config');

const ssoConfig = config.get('sso');

const getKey = function getKey(header, callback) {
  const client = jwksClient({
    jwksUri: 'https://identity.robotti.private/realms/master/protocol/openid-connect/certs',
    requestAgent: new https.Agent({
      ca: fs.readFileSync(path.resolve(ssoConfig.caPath))
    })
  });
  client.getSigningKey(header.kid, (err, key) => {
    try {
      if (err) {
        // logger.error('Unable to retrieve signing cert', {
        //   request: {
        //     error: err.toString()
        //   }
        // });
        return callback(null, null);
      }
      const signingKey = key.publicKey || key.rsaPublicKeyPublicKey;
      return callback(null, signingKey);
    } catch {
      // logger.error('Unable to retrieve signing cert', {
      //   request: {
      //     error: err.toString()
      //   }
      // });
      return callback(null, null);
    }
  });
};

module.exports = (req, res, next) => {
  try {
    if (!req.headers.authorization || req.headers.authorization.indexOf('Bearer ') < 0 || req.headers.authorization.length < 8) {
      // logger.error('Invalid authorization token', {
      //   request: {
      //     headers: req.headers
      //   }
      // });
      return res.status(401).send('Invalid authorization token provided');
    }
    return jwt.verify(req.headers.authorization.slice(req.headers.authorization.indexOf(' ') + 1), getKey, {}, (err, decoded) => {
      if (err || !decoded?.realm_access?.roles || decoded.realm_access.roles.indexOf('fileservice') < 0 || decoded.realm_access.roles.indexOf(ssoConfig.environment) < 0) {
        // logger.error('Unauthorized request', {
        //   request: {
        //     error: err ? err.toString() : 'Unauthorized',
        //     data: decoded
        //   }
        // });
        return res.status(401).send('Unauthorized request');
      }
      return next();
    });
  } catch (err) {
    // logger.error('Unexpected error occured', {
    //   request: {
    //     error: err.toString()
    //   }
    // });
    return res.status(500).send('An unexpected error occured');
  }
};
