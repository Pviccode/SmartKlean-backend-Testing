const { body } = require('express-validator');
const jwt = require("jsonwebtoken");

const User = require('../models/User.js');
const { sanitizeInputs, handleValidationErrors, handleGenericErrors, requestRateLimiter } = require('../auth/auth-security.js');
const { validateEmail, isStrongPassword } = require('../utils/validation');
const sendEmail = require('../utils/sendEmailUtil.js');
const { maskEmail, formatUserResponse } = require('../utils/otherUtils.js');
const logger = require('../config/logger.js');

// Validate environment variables
if (!process.env.FRONTEND_URL || !process.env.JWT_SECRET) {
    logger.error('FRONTEND_URL, or JWT_SECRET in environment variables');
    process.exit(1);
};

// Input validation middlewares
const validateLogin = [
    validateEmail,
    body('password')
      .trim()
      .notEmpty()
      .withMessage('Password is required')
      .isLength({ min: 8, max: 128 })
      .withMessage('Password must be between 8 and 128 characters long.')
];

const validatePasswordResetRequest = [
    validateEmail,
]

const validateResetPassword = [
    body('token')
      .trim()
      .notEmpty()
      .withMessage('Reset token is required'),
    body('password')
      .trim()
      .notEmpty()
      .isLength({ min: 8, max: 128 })
      .custom(isStrongPassword),
];

// Login user
const postLogin = [
    requestRateLimiter(5, '/auth/login', 'login attempts'),
    sanitizeInputs,
    validateLogin,
    handleValidationErrors,
    async (req, res) => {

        try {
            const { email, password } = req.body;

            // Checks if a user with the provided email exists.
            const user = await User.findOne({ email: email.toLowerCase() }).select('+password');  // Explicitly includes the password field from the user document

            // If no user is found, returns a 401 bad request
            if (!user) {
                logger.warn(`Login attempt with non-existent email: ${maskEmail(email)}`);
                return res.status(401).json({ 
                    status: 'error',
                    message: 'Please provide a valid email address and password' 
                });
            }

            // Check if user is verified
            if (!user.isVerified) {
                logger.warn(`Login attempt by unverified user: ${maskEmail(email)}`);
                return res.status(403).json({
                    status: 'error',
                    message: 'Please verify your email before logging in.',
                });
            }

            // Check if account is locked due to too many failed attempts
            if (user.failedLoginAttempts >= 5) {
                logger.warn(`Account locked due to too many failed login attempts: ${maskEmail(email)}`);
                return res.status(403).json({
                    status: 'error',
                    message: 'Account temporarily locked. Please try again later or reset your password.'
                });
            };

            // Verifies the provided password against the stored hashed password.
            const isPasswordMatch = await user.comparePassword(password);
            if (!isPasswordMatch) {
                // Increment failed login attempts
                user.failedLoginAttempts += 1;
                user.lastFailedLogin = new Date();
                await user.save();

                logger.warn(`Failed login attempt for verified user: ${maskEmail(email)}`);
                return res.status(401).json({ 
                    status: 'error',
                    message: 'Please provide a valid email address and password' 
                });
            }

            // Reset failed login attempts on successful login
            if (user.failedLoginAttempts > 0) {
                user.failedLoginAttempts = 0;
                user.lastLogin = new Date();
                await user.save();
            }

            // Generate JWT. The JWT allows the client to authenticate future requests by validating the user’s identity and role.
            const payload = { id: user._id, role: user.role, email: user.email };

            // Signing the payload object with a secret key
            const token = jwt.sign(payload, process.env.JWT_SECRET, { 
                expiresIn: '1h',
                issuer: process.env.JWT_ISSUER,     // To verify that the token is sent from a trusted authority
                audience: process.env.JWT_AUDIENCE, // To prevent token reuse between services (e.g. a token meant for one app shouldn't work in another)
            });  

            // Stores the JWT in a cookie named auth_token for secure transmission to the client.
            res.cookie("auth_token", token, { 
                httpOnly: true,                                   // Prevents client-side JavaScript from accessing the cookie, reducing XSS attack risks.
                secure: process.env.NODE_ENV === "production",   // Ensures the cookie is only sent over HTTPS in production (not in development).
                sameSite: 'strict',                             // Prevent CSRF attacks
                maxAge: 3600000,                               // Sets the cookie’s lifespan to 1 hour (3600000 milliseconds), matching the JWT’s expiration.
            });

            // Log sucessful login by user
            logger.info(`Successful login for: ${maskEmail(email)}`);

            // Returns this response if login is successfull
            return res.status(200).json({
                status: 'success',
                message: 'User logged in successfully', 
            });

        // Catches any errors during the login process (e.g., database issues, network issues).
        } catch (error) {
            logger.error(`Login request error: ${error.message}`);
            return handleGenericErrors(error, res, 'login');
        }
    }
];


// This function retrieves the details of the currently authenticated user.
const getCurrentUser = [
    requestRateLimiter(100, '/auth/user', 'requests'),
    async (req, res) => {

        // Check if user is authenticated
        if (!req.user || !req.user.id) {
            logger.warn(`Unauthenticated user: for IP ${req.ip}`);
            return res.json({ 
                isAuthenticated: false,
                message: 'Unauthenticated user: No valid user session', 
                user: null 
            });
        }

        const id = req.user.id;           // Uses req.user.id, which is set by the auth middleware.

        try {
            // Retrieves the user document from the database by _id, excluding sensitive fields like password and version key field from the returned document for security purpose, ensuring sensitive data isn’t sent to the client. 
            const user = await User.findById(id).select('-password -__v');
            if (!user) {
                logger.warn(`User not found for ID: ${id}`);
                return res.status(404).json({ 
                    isAuthenticated: false, 
                    message: 'User not found', 
                    user: null 
                });
            }

            // Log successful retrieval of authenticated user's details
            logger.info(`User details retrieved for ID: ${id}, email: ${maskEmail(user.email)}`);

            // Return formatted user data
            return res.status(200).json({ 
                isAuthenticated: true,
                message: 'User details retrieved successfully',
                user: formatUserResponse(user),                  // An object with user details (name, email, role, and createdAt), excluding sensitive data like the password. This object is then sent to the client.
            });

        } catch (error) {
            logger.error(`Unexpected error occurred during access to the /auth/user route (ID: ${id}): ${error.stack}`);
            return res.status(500).json({ 
                isAuthenticated: false,
                message: 'Internal server error. Please try again later.',
                user: null
            });
        }
    }
];

// Logout user
const postLogout = async (req, res) => {
    try {
        // Clear the authentication cookie
        res.clearCookie('auth_token', {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict'
        });

        // Log successful logout
        logger.info(`User logged out successfully for IP ${req.ip}`);

        // Return standardized response
        return res.status(200).json({
            isAuthenticated: false,
            message: 'Logged out successfully',
            user: null
        });
    } catch (error) {
        logger.error(`Logout request error: ${error.message}`);
        return handleGenericErrors(error, res, `logout for IP ${req.ip}`);
    }
};

// Request password reset
const postRequestPasswordReset = [
    requestRateLimiter(5, '/auth/request-password-reset', 'reset attempts'),
    sanitizeInputs,
    validatePasswordResetRequest,
    handleValidationErrors,
    async (req, res) => {
        try {
            const { email } = req.body;
            logger.info(`Password reset request for email: ${maskEmail(email)}`);

            const user = await User.findOne({ email: email.toLowerCase() });

            if (!user) {
                logger.warn(`Password reset requested for non-existent email: ${maskEmail(email)}`);

                // For security sake, return a 200 OK response even if the email doesn't exist to prevent attackers from guessing registered emails.
                return res.status(200).json({
                    status: 'success',
                    message: 'If an account exists, a password reset link has been sent to your email.'
                });
            }

            if (!user.isVerified) {
                logger.warn(`Password reset requested for unverified user: ${maskEmail(email)}`);
                return res.status(400).json({
                    status: 'error',
                    message: 'Please verify your email before resetting your password.'
                });
            }

            // Generate reset token
            const resetToken = jwt.sign({ email: user.email}, process.env.JWT_SECRET, { 
                expiresIn: '1h',
                issuer: process.env.JWT_ISSUER,
                audience: process.env.JWT_AUDIENCE, 
            });
            const tokenExpiration = new Date(Date.now() + 60 * 60 * 1000);

            user.resetPasswordToken = resetToken;
            user.resetPasswordExpires = tokenExpiration;
            await user.save();

            // Send password reset email
            try {
                const resetLink = new URL('/reset-password', process.env.FRONTEND_URL);
                resetLink.searchParams.append('token', resetToken);

                await sendEmail({
                    to: user.email,
                    subject: 'Reset your Password - SmartKlean Cleaning Services',
                    html: `
                      <!DOCTYPE html>
                      <html lang="en">
                        <head>
                          <meta charset="UTF-8">
                          <meta name="viewport" content="width=device-width, initial-scale=1.0">
                          <title>Password Reset</title>
                        </head>
                        <body 
                          style="font-family: Arial, sans-serif;
                          color: #333; margin: 0; padding: 20px;"
                        > 
                          <div 
                            style="max-width: 600px; margin: auto;
                            border: 1px solid #e0e0e0; border-radius: 5px; padding: 20px;"
                          >
                            <h1 style="color: #007bff;">Hello, ${sanitizeHtml(firstName)} ${sanitizeHtml(lastName)}</h1>
                            <p>We received a request to reset your password.</p>
                            <p>Please click the button below to set a new password:</p>
                            <a 
                              href="${resetLink.toString()}"
                              style="display: inline-block; padding: 12px 24px; background-color: #007bff;
                              color: #ffffff; text-decoration: none; border-radius: 5px; font-weight: bold;"
                            >
                              Reset Password
                            </a>
                            <p style="margin-top: 15px">If the button doesn't work, copy and paste this link into your browser:</p>
                            <p style="word-break: break-all;>
                              <a href="${resetLink.toString()}" style="color: #007bff;">${resetLink.toString()}</a>
                            </p>
                            <p>This link will expire in 1 hour.</p>
                            <p>If you did not request this, please ignore this email.</p>
                            <hr style="border-top: 1px solid #e0e0e0; margin: 20px 0;">
                            <p>© ${new Date().getFullYear()} SmartKlean Cleaning Services. All rights reserved.</p>
                          </div>
                          
                        </body>
                      </html>
                    `,
                });

                logger.info(`Password reset email sent to ${maskEmail(user.email)}`);

            } catch (emailError) {
                logger.error(`Failed to send password reset email to ${maskEmail(user.email)}: ${emailError.message}`);
                return res.status(500).json({
                    status: 'error',
                    message: 'Failed to send Password reset email. Please try again.',
                });
            }

            return res.status(200).json({
                status: 'success',
                message: 'A password reset link has been sent to your email.'
            });

        } catch (error) {
            logger.error(`Password reset request error: ${error.message}`);
            handleGenericErrors(error, res, 'password reset request');
        }
    }
];

// Reset password
const postResetPassword = [
    sanitizeInputs,
    validateResetPassword,
    handleValidationErrors,
    async (req, res) => {
        try {
            const { token, password } = req.body;
            logger.info(`Password reset attempt with token: ${token ? token.slice(0, 20) + '...' : 'none'}`);

            if (!token) {
                logger.warn('No reset token provided');
                return res.status(400).json({
                    status: 'error',
                    message: 'Invalid reset link'
                });
            }

            let decoded;
            try {
                decoded = jwt.verify(token, process.env.JWT_SECRET);
                logger.info(`Decoded JWT email for password reset: ${maskEmail(decoded.email)}`);

            } catch (jwtError) {
                logger.warn(`Invalid or expired JWT token for password reset: ${token.slice(0, 20)}...`);
                return res.status(400).json({
                    status: 'error',
                    message: 'Invalid or expired reset token. Please request a new reset link.'
                });
            }

            const user = await User.findOne({
                email: decoded.email,
                resetPasswordToken: token,
                resetPasswordExpires: { $gt: new Date() },
            });

            if (!user) {
                logger.warn(`User not found or token expired for password reset: ${maskEmail(decoded.email)}`);
                return res.status(400).json({
                    status: 'error',
                    message: 'Invalid or expired reset token. Please request a new reset link.'
                });
            }

            user.password = password;            // Will be hashed by pre-save middleware
            user.resetPasswordToken = null;
            user.resetPasswordExpires = null;
            await user.save();

            logger.info(`Password reset successful for: ${maskEmail(user.email)}`);

            return res.status(200).json({
                status: 'success',
                message: 'Password reset successfully. You can now log in with your new password.'
            });

        } catch (error) {
            logger.error(`Password reset error: ${error.message}`);
            return handleGenericErrors(error, res, 'Password reset');
        }
    }
];

module.exports = { 
    postLogin, 
    getCurrentUser, 
    postLogout, 
    postRequestPasswordReset, 
    postResetPassword 
};