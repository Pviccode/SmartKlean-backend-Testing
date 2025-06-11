const winston = require('winston');

// Initialize logger for security audits
const logger = winston.createLogger({
    level: 'info',  // Log messages at 'info' level and above
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()   // Output logs as JSON
    ),
    transports: [
        // Log to console
        new winston.transports.Console(),
        // Log errors to error.log
        new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
        // Log all messages to combined.log
        new winston.transports.File({ filename: 'logs/combined.log' })
    ],
});

// Development-specific console logging
if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
      format: winston.format.simple(),
    }));
}

module.exports = logger;