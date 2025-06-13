const { validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const sanitize = require('mongo-sanitize');
const logger = require('../config/logger');

// Sanitize user input middleware to protect against MongoDB-specific injection attacks,
const sanitizeInputs = (req, next) => {
    if (req.body) {
        req.body = sanitize(req.body);
    }
    next();
};

// Validation error middleware
const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        logger.warn(`Validation failed: ${JSON.stringify(errors.array())}`);
        return res.status(400).json({
            status: 'error',
            message: 'Validation failed',
            errors: errors.array(),
        });
    }
    next();
};

// Rate limiting middleware to limit too many repeated requests from a single client to a route or endpoint
const requestRateLimiter = (maxRequests, endpoint, context) => {
    return rateLimit({
      windowMs: 15 * 60 * 1000,  // 15 minutes
      max: maxRequests,
      handler: (req, res) => {
        logger.warn(`Rate limit exceeded from IP ${req.ip} on ${endpoint}`);
        res.status(429).json({
            status: 'error',
            message: `Too many ${context}, please try again later.`,
        });
      }
    });
}

// Generic error handler
const handleGenericErrors = (error, res, context = 'operation') => {
    logger.error(`Unexpected error occurred during ${context}: ${error.stack}`);
    return res.status(500).json({
        status: 'error', 
        message: 'Something went wrong. Please try again later.' 
    });
};

module.exports = {
    sanitizeInputs,
    handleValidationErrors,
    requestRateLimiter,
    handleGenericErrors
};