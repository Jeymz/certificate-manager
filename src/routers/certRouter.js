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
    if (!req.body || typeof req.body !== 'object') {
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
    } = req.body;

    const newCert = await controller.newWebServerCertificate(
      hostname,
      passphrase,
      altNames,
      bundleP12,
      password,
    );
    return res.status(200).json(newCert);
  } catch (err) {
    logger.error(`Error creating certificate: ${err.message}`);
    return res.status(400).send({ error: 'Unable to process request' });
  }
});

router.post('/intermediate', async(req, res) => {
  try {
    if (!req.body || typeof req.body !== 'object') {
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
    const ca = await controller.newIntermediateCA(hostname, passphrase, intermediatePassphrase);
    return res.status(200).json(ca);
  } catch (err) {
    logger.error(`Error creating intermediate CA: ${err.message}`);
    return res.status(400).send({ error: 'Unable to process request' });
  }
});

router.post('/revoke', async(req, res) => {
  try {
    if (!req.body || typeof req.body !== 'object') {
      logger.error('Invalid request body: must be an object');
      return res.status(400).send({ error: 'Invalid request body' });
    }
    const validator = config.getValidator();
    if (!validator.validateSchema('revoke', req.body)) {
      logger.error('Invalid request body: schema validation failed');
      return res.status(400).send({ error: 'Invalid request body: schema validation failed' });
    }
    const { serialNumber, reason } = req.body;
    const result = await controller.revokeCertificate(serialNumber, reason);
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
