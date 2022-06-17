const express = require('express');
const bodyParser = require('body-parser');

const app = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

const certRouter = require('./routers/certRouter')();

app.use('/', certRouter);

module.exports = app;
