const app = require('./src/app');
const config = require('./src/resources/config')();

const serverConfig = config.getServerConfig();

const { port } = serverConfig;

app.listen(port, (err) => {
  if (err) {
    console.log(err);
  } else {
    console.log(`Listening on port: ${port}`);
  }
});
