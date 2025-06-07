const app = require('./src/app');
const config = require('./src/resources/config')();
const logger = require('./src/utils/logger');

const serverConfig = config.getServerConfig();

const { port } = serverConfig;

app.listen(port, (err) => {
  if (err) {
    logger.error(`Error starting server: ${err}`);
    process.exit(1);
  } else {
    logger.info(`Server is running on port ${port}`);
  }
});
