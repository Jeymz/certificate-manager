const { createLogger, format, transports } = require('winston');

const loggerTransports = [
  new transports.Console({
    format: format.combine(
      format.colorize(),
      format.simple(),
    ),
  }),
];

if (process.env.LOG_FILE) {
  loggerTransports.push(
    new transports.File({ filename: process.env.LOG_FILE }),
  );
}

const logger = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  transports: loggerTransports,
});

module.exports = logger;
