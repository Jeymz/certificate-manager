const express = require('express');
const controller = require('../controllers/certController');
const config = require('../resources/config')();
const logger = require('../utils/logger');

const router = express.Router();

module.exports = () => {
    router.route('/new')
      .post((req, res) => {
        if (!req.body || typeof req.body !== 'object') {
          return res.status(400).send({
            error: 'Invalid request body',
          });
        }
      const validator = config.getValidator();
      if (!validator.validateSchema('new', req.body)) {
        return res.status(400).send('Invalid request body');
      }
      const {
        hostname,
        altNames,
        passphrase,
      } = req.body;
      try {
        const newCert = controller.newWebServerCertificate(hostname, passphrase, altNames);
        return res.send(newCert);
      } catch (err) {
        logger.error(`Error creating certificate: ${err.message}`);
        return res.status(400).send({ error: 'Unable to process request' });
      }
      });

  router.route('/')
    .get((req, res) => {
      if (config.isInitialized() === true) {
        res.send('Ready');
      } else {
        res.send('Awaiting Setup');
      }
    });

  return router;
};
