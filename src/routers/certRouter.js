const express = require('express');
const controller = require('../controllers/certController');
const config = require('../resources/config')();

const router = express.Router();

module.exports = () => {
  router.route('/new')
    .post((req, res) => {
      if (!req.body || typeof req.body !== 'object') {
        return res.status(400).send({
          error: 'Invalid request body'
        });
      }
      const validator = config.getValidator();
      if (!validator.validateSchema('new', req.body)) {
        return res.status(400).send('Invalid request body');
      }
      const {
        hostname,
        altNames,
        passphrase
      } = req.body;
      const newCert = controller.newWebServerCertificate(hostname, passphrase, altNames);
      return res.send(newCert);
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
