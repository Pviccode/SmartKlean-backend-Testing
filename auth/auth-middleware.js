const verifyJwtToken = require('../utils/jwtVerify');
const logger = require('../config/logger');
const { maskEmail } = require('../utils/otherUtils.js');

// This authentication middleware ensures that only authenticated users (those with a valid JWT) can access protected routes.
const auth = async (req, res, next) => {
    const token = req.cookies.auth_token;
    const { isValid, decoded, error} = verifyJwtToken(token);

    if (!isValid) {
        req.user = null;
        if (error === 'Expired token') {
            req.tokenExpired = true;
            return res.status(401).json({
                isAuthenticated: false,
                message: 'Token expired, please log in again',
                user: null,
            });
        }
        return res.status(error === 'No token provided' ? 401 : 500).json({
            isAuthenticated: false,
            message: error || 'Internal server error during authentication',
            user: null
        });
    }

    // If JWT token is valid, attaches the decoded JWT payload to the req object as req.user.
    req.user = decoded;
    next();
};

// Admin access middleware. This middleware ensures that only users with the "admin" role can access certain routes.
const requireAdmin = (req, res, next) => {
    // Check if user is authenticated
    if (!req.user || !req.user.id) {
        logger.warn('Admin access attempted without authentication');
        return res.status(401).json({
            isAuthenticated: false,
            message: 'Authentication required for admin access',
            user: null
        });
    }

    // Check if authenticated user has admin role. Verifies that the role property in req.user (set by the auth middleware) is "admin".
    if (req.user.role !== 'admin') {
        logger.warn(`Non-admin authenticated user attempted admin access: ID=${req.user.id}, email=${maskEmail(req.user.email)}`)
        return res.status(403).json({ 
            isAuthenticated: true,
            message: 'Admin access required',
            user: null
        });
    }

    next();
};

module.exports = { auth, requireAdmin };

