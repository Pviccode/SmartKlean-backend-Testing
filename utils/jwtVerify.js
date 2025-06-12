const jwt = require("jsonwebtoken");
const logger = require('../config/logger');

const verifyJwtToken = (token) => {

    // Verifies that a token exists.
    if (!token) {
        logger.warn('No JWT token');
        return {
            isValid: false,
            decoded: null,
        };
    }

    try {
        // Verify the token if it exists and confirms that the token is valid and was issued by the server.
        const decoded = jwt.verify(token, process.env.JWT_SECRET, {
            issuer: process.env.JWT_ISSUER,
            audience: process.env.JWT_AUDIENCE
        }); 
        
        return {
            isValid: true,
            decoded
        };

    } catch (error) {
        // Occurs if the JWT has expired (based on the exp claim in the token).
        if (error.name === 'TokenExpiredError') {
            logger.warn(`Expired JWT token: ${error.message}`);
            return {
                isValid: false,
                decoded: null,
            };
        }

        // For other errors (e.g., invalid signature, malformed token)
        logger.error(`JWT verification error: ${error.stack}`);
        return {
            isValid: false,
            decoded: null,
        };
    }
};

module.exports = verifyJwtToken;