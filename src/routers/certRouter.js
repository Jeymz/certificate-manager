const express = require('express');
const controller = require('../controllers/certController');
const config = require('../resources/config')();
const logger = require('../utils/logger');

/**
 * Express router exposing certificate issuance endpoints.
 */
const router = express.Router();



router.post('/new', async(req, res) => {
  try {
    if (!req.body || typeof req.body !== 'object' || Object.keys(req.body).length === 0) {
      logger.error('Invalid request body: must be an object');
      return res.status(400).send({
        error: 'Invalid request body',
      });
    }
    const validator = config.getValidator();
    if (!validator.validateSchema('new', req.body)) {
      logger.error('Invalid request body: schema validation failed');
      return res.status(400).send({
        error: 'Invalid request body: schema validation failed',
      });
    }
    const {
      hostname,
      altNames,
      passphrase,
      bundleP12,
      password,
      validityDays,
    } = req.body;

    // Enforce validity limits from config (safe when tests use a mock config)
    const limits = (config.getValidityLimits && config.getValidityLimits()) || { minDays: 1, maxDays: 397 };
    const profileDefault = (config.getProfileValidity && config.getProfileValidity('webServer')) || null;
    let finalValidity = null;
    if (typeof validityDays !== 'undefined' && validityDays !== null) {
      if (validityDays < limits.minDays || validityDays > limits.maxDays) {
        logger.error(`Requested validityDays ${validityDays} out of allowed range`);
        return res.status(400).send({ error: `validityDays must be between ${limits.minDays} and ${limits.maxDays}` });
      }
      finalValidity = validityDays;
    } else if (profileDefault) {
      // use profile default if configured (still enforce limits)
      if (profileDefault < limits.minDays || profileDefault > limits.maxDays) {
        logger.error(`Configured profile default validityDays ${profileDefault} out of allowed range`);
        return res.status(500).send({ error: 'Invalid server configuration for profile validity' });
      }
      finalValidity = profileDefault;
    }

    let newCert;
    if (finalValidity === null) {
      // deepcode ignore PT: All request body parameters are validated by the schema on line 22
      newCert = await controller.newWebServerCertificate(
        hostname,
        passphrase,
        altNames,
        bundleP12,
        password,
        req.ip,
      );
    } else {
      // deepcode ignore PT: All request body parameters are validated by the schema on line 22
      newCert = await controller.newWebServerCertificate(
        hostname,
        passphrase,
        altNames,
        bundleP12,
        password,
        finalValidity,
        req.ip,
      );
    }
    return res.status(200).json(newCert);
  } catch (err) {
    logger.error(`Error creating certificate: ${err.message}`);
    return res.status(400).send({ error: 'Unable to process request' });
  }
});

router.post('/ldap', async(req, res) => {
  try {
    if (!req.body || typeof req.body !== 'object' || Object.keys(req.body).length === 0) {
      logger.error('Invalid request body: must be an object');
      return res.status(400).send({
        error: 'Invalid request body',
      });
    }
    const validator = config.getValidator();
    if (!validator.validateSchema('ldap', req.body)) {
      logger.error('Invalid request body: schema validation failed');
      return res.status(400).send({
        error: 'Invalid request body: schema validation failed',
      });
    }
    const {
      hostname,
      altNames,
      passphrase,
      bundleP12,
      password,
      validityDays,
    } = req.body;

    // Enforce validity limits from config for LDAP profile
    const limitsLdap = (config.getValidityLimits && config.getValidityLimits()) || { minDays: 1, maxDays: 397 };
    const profileDefaultLdap = (config.getProfileValidity && config.getProfileValidity('ldapServer')) || null;
    let finalValidityLdap = null;
    if (typeof validityDays !== 'undefined' && validityDays !== null) {
      if (validityDays < limitsLdap.minDays || validityDays > limitsLdap.maxDays) {
        logger.error(`Requested validityDays ${validityDays} out of allowed range`);
        return res.status(400).send({ error: `validityDays must be between ${limitsLdap.minDays} and ${limitsLdap.maxDays}` });
      }
      finalValidityLdap = validityDays;
    } else if (profileDefaultLdap) {
      if (profileDefaultLdap < limitsLdap.minDays || profileDefaultLdap > limitsLdap.maxDays) {
        logger.error(`Configured profile default validityDays ${profileDefaultLdap} out of allowed range`);
        return res.status(500).send({ error: 'Invalid server configuration for profile validity' });
      }
      finalValidityLdap = profileDefaultLdap;
    }

    let newCertLdap;
    if (finalValidityLdap === null) {
      // deepcode ignore PT: All request body parameters are validated by the schema on line 96
      newCertLdap = await controller.newLdapServerCertificate(
        hostname,
        passphrase,
        altNames,
        bundleP12,
        password,
        req.ip,
      );
    } else {
      // deepcode ignore PT: All request body parameters are validated by the schema on line 96
      newCertLdap = await controller.newLdapServerCertificate(
        hostname,
        passphrase,
        altNames,
        bundleP12,
        password,
        finalValidityLdap,
        req.ip,
      );
    }
    return res.status(200).json(newCertLdap);
  } catch (err) {
    logger.error(`Error creating certificate: ${err.message}`);
    return res.status(400).send({ error: 'Unable to process request' });
  }
});

router.post('/intermediate', async(req, res) => {
  try {
    if (!req.body || typeof req.body !== 'object' || Object.keys(req.body).length === 0) {
      logger.error('Invalid request body: must be an object');
      return res.status(400).send({ error: 'Invalid request body' });
    }
    const validator = config.getValidator();
    if (!validator.validateSchema('intermediate', req.body)) {
      logger.error('Invalid request body: schema validation failed');
      return res.status(400).send({ error: 'Invalid request body: schema validation failed' });
    }
    const {
      hostname,
      passphrase,
      intermediatePassphrase,
    } = req.body;
    // deepcode ignore PT: The hostname is validated by the schema on line 57
    const ca = await controller.newIntermediateCA(hostname, passphrase, intermediatePassphrase, req.ip);
    return res.status(200).json(ca);
  } catch (err) {
    logger.error(`Error creating intermediate CA: ${err.message}`);
    return res.status(400).send({ error: 'Unable to process request' });
  }
});

router.post('/revoke', async(req, res) => {
  try {
    if (!req.body || typeof req.body !== 'object' || Object.keys(req.body).length === 0) {
      logger.error('Invalid request body: must be an object');
      return res.status(400).send({ error: 'Invalid request body' });
    }
    const validator = config.getValidator();
    if (!validator.validateSchema('revoke', req.body)) {
      logger.error('Invalid request body: schema validation failed');
      return res.status(400).send({ error: 'Invalid request body: schema validation failed' });
    }
    const { serialNumber, reason } = req.body;
    const result = await controller.revokeCertificate(serialNumber, reason, req.ip);
    if (result.error) {
      return res.status(404).send(result);
    }
    return res.status(200).json(result);
  } catch (err) {
    logger.error(`Error revoking certificate: ${err.message}`);
    return res.status(400).send({ error: 'Unable to process request' });
  }
});

router.get('/crl', async(req, res) => {
  try {
    const list = await controller.getCRL();
    return res.status(200).json(list);
  } catch (err) {
    logger.error(`Error retrieving CRL: ${err.message}`);
    return res.status(400).send({ error: 'Unable to process request' });
  }
});

router.get('/crl.pem', async(req, res) => {
  try {
    const crlPem = await controller.getCRLPem();
    res.set('Content-Type', 'application/pkix-crl');
    return res.status(200).send(crlPem);
  } catch (err) {
    logger.error(`Error generating CRL: ${err.message}`);
    return res.status(400).send({ error: 'Unable to process request' });
  }
});

router.get('/', (req, res) => {
  if (config.isInitialized() === true) {
    return res.send('Ready');
  } 
  return res.send('Awaiting Setup');
});

/**
 * Export the configured router for mounting in an Express app.
 *
 * @type {import('express').Router}
 */
module.exports = router;
