/**
 * Entry point for the certificate manager HTTP server.
 */
const app = require('./src/app');
const config = require('./src/resources/config')();
const logger = require('./src/utils/logger');
const { validateStore } = require('./src/utils/storeValidator');

const serverConfig = config.getServerConfig();

const { port } = serverConfig;

validateStore(config.getStoreDirectory())
  .catch((err) => {
    logger.error(`Store validation failed: ${err.message}`);
    process.exit(1);
  });

app.listen(port, (err) => {
  if (err) {
    logger.error(`Error starting server: ${err}`);
    process.exit(1);
  } else {
    logger.info(`Server is running on port ${port}`);
  }
});
