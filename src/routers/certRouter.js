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
    } = req.body;
    
    const newCert = await controller.newWebServerCertificate(hostname, passphrase, altNames);
    return res.send(newCert);
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
    if (!validator.validateSchema('new', req.body)) {
      logger.error('Invalid request body: schema validation failed');
      return res.status(400).send({ error: 'Invalid request body: schema validation failed' });
    }
    const { hostname, passphrase } = req.body;
    const ca = await controller.newIntermediateCA(hostname, passphrase);
    return res.send(ca);
  } catch (err) {
    logger.error(`Error creating intermediate CA: ${err.message}`);
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
