/**
 * Entry point for the certificate manager HTTP server.
 */
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const app = require('./src/app');
const config = require('./src/resources/config')();
const logger = require('./src/utils/logger');
const { validateStore } = require('./src/utils/storeValidator');

const serverConfig = config.getServerConfig();

const {
  port,
  protocol = 'https',
  key,
  cert,
} = serverConfig;

validateStore(config.getStoreDirectory())
  .catch((err) => {
    logger.error(`Store validation failed: ${err.message}`);
    process.exit(1);
  });

let server;
if (protocol === 'https') {
  const options = {
    key: fs.readFileSync(path.resolve(key)),
    cert: fs.readFileSync(path.resolve(cert)),
  };
  server = https.createServer(options, app);
} else {
  server = http.createServer(app);
}

server.listen(port, (err) => {
  if (err) {
    logger.error(`Error starting server: ${err}`);
    process.exit(1);
  } else {
    logger.info(`Server is running on port ${port} using ${protocol.toUpperCase()}`);
  }
});
