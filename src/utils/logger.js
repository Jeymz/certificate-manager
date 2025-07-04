const { createLogger, format, transports } = require('winston');

/**
 * Application-wide Winston logger instance.
 * @module logger
 */

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

const auditTransports = [];
auditTransports.push(new transports.Console({ format: format.json() }));
if (process.env.AUDIT_LOG_FILE) {
  auditTransports.push(new transports.File({
    filename: process.env.AUDIT_LOG_FILE,
    format: format.combine(format.timestamp(), format.json()),
    maxsize: 1048576,
    maxFiles: 5,
  }));
}

const auditLogger = createLogger({
  level: 'info',
  format: format.combine(format.timestamp(), format.json()),
  transports: auditTransports,
});

logger.audit = auditLogger;

/**
 * Shared logger instance.
 *
 * @type {import('winston').Logger}
 */
module.exports = logger;
