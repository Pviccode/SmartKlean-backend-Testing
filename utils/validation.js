const { body } = require('express-validator');

// Email regex pattern
const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

// Password regex pattern
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

// Email validation middleware
const validateEmail = body('email')
    .trim()
    .notEmpty()
    .withMessage('Email is required')
    .isEmail()
    .normalizeEmail()
    .withMessage('Invalid email address')
    .custom((email) => {
        if (!EMAIL_REGEX.test(email)) {
            throw new Error('Invalid email format.')
        }
        return true
    });

// Strong password validator
const isStrongPassword = (password) => {
    return PASSWORD_REGEX.test(password);
};

module.exports = { EMAIL_REGEX, validateEmail, isStrongPassword };


