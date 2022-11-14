const express = require('express');
const middleware = require('../resources/middleware/main');

const router = express.Router();
router.use(middleware.token);

module.exports = (controller) => {
  router.route('/')
    .get(controller.getCert)
    .post(controller.postCert)
    .delete(controller.deleteCert);

  return router;
};
