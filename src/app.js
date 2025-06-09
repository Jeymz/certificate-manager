const express = require('express');
const bodyParser = require('body-parser');

/**
 * Express application instance.
 */
const app = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

const certRouter = require('./routers/certRouter');

app.use('/', certRouter);

/**
 * Export the configured Express application for server startup and testing.
 *
 * @type {import('express').Application}
 */
module.exports = app;
