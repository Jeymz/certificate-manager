const express = require('express');
const bodyParser = require('body-parser');

const app = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

const routers = require('./routers/main');
const controllers = require('./controllers/main');

app.route('/api/cert', routers.cert(controllers.cert));

module.exports = app;
