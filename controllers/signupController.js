const { body } = require('express-validator');
const sanitizeHtml = require('sanitize-html');
const jwt = require('jsonwebtoken');

const User = require('../models/User.js');
const { sanitizeInputs, handleValidationErrors, handleGenericErrors, requestRateLimiter } = require('../auth/auth-security.js');
const { validateEmail, isStrongPassword } = require('../utils/validation');
const sendEmail = require('../utils/sendEmailUtil.js');
const { maskEmail } = require('../utils/otherUtils.js');
const logger = require('../config/logger.js');

// Validate environment variables
if (!process.env.FRONTEND_URL || !process.env.JWT_SECRET) {
    logger.error('FRONTEND_URL, or JWT_SECRET in environment variables');
    process.exit(1);
};

// Input validation middleware for signup
const validateSignup = [
    body('firstName')
      .trim()
      .notEmpty()
      .withMessage('First name is required')
      .isLength({ min: 2, max: 50 })
      .withMessage('First name must be between 2 and 50 characters'),
    body('lastName')
      .trim()
      .notEmpty()
      .withMessage('Last name is required')
      .isLength({ min: 2, max: 50 })
      .withMessage('Last name must be between 2 and 50 characters'),
    validateEmail,
    body('password')
      .trim()
      .notEmpty()
      .withMessage('Password is required')
      .isLength({ min: 8, max: 128 })
      .withMessage('Password must be between 8 and 128 characters long.')
      .custom(isStrongPassword)
      .withMessage('Password must include uppercase, lowercase, number, and special character.')
];

// Input validation for email verification resend
const validateResend = [
    body('token')
      .trim()
      .notEmpty()
      .withMessage('Verification token is required'),
];

// Register new user.
exports.postSignup = [
    requestRateLimiter(5, '/auth/signup', 'signup attempts'),
    // sanitizeInputs,
    validateSignup,
    handleValidationErrors,
    async (req, res) => {
        try {
            const { firstName, lastName, email, password } = req.body;

            // Checks if a user with the provided email already exists in the database.
            const user = await User.findOne({ email });
            if (user) {
                logger.warn(`Signup attempt with existing email: ${maskEmail(email)}`);
                return res.status(400).json({ 
                    status: 'error', 
                    message: 'Account already exists' 
                });
            }

            // Generate verification token
            const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET, { 
                expiresIn: '24h',
                issuer: process.env.JWT_ISSUER,
                audience: process.env.JWT_AUDIENCE, 
            });
            const tokenExpiration = new Date(Date.now() + 24 * 60 * 60 * 1000);

            // If a user with such email doesn't exist, creates a new User document with additional security checks.
            const newUser = new User({ 
                firstName: firstName.trim(), 
                lastName: lastName.trim(), 
                email: email.toLowerCase(), 
                password,
                verificationToken,
                verificationTokenExpires: tokenExpiration
            });

            // Save new user with transaction for data consistency and integrity
            const session = await User.startSession();
            try {
                await session.withTransaction(async () => {
                    await newUser.save({ session });     
                })
            } finally {
                session.endSession();
            }

            // Log successful signup
            logger.info(`New user created: ${maskEmail(email)}`);

            // Send verification email
            try {
                const verificationLink = new URL('/verify', process.env.FRONTEND_URL);
                verificationLink.searchParams.append('token', verificationToken);

                await sendEmail({
                    to: email,  // User's email
                    subject: 'Verify your Account - SmartKlean Cleaning Services!',
                    html: `
                      <!DOCTYPE html>
                      <html lang="en">
                        <head>
                          <meta charset="UTF-8">
                          <meta name="viewport" content="width=device-width, initial-scale=1.0">
                          <title>Account Verification</title>
                        </head>
                        <body 
                          style="font-family: Arial, sans-serif;
                          color: #333; margin: 0; padding: 20px;"
                        > 
                          <div 
                            style="max-width: 600px; margin: auto;
                            border: 1px solid #e0e0e0; border-radius: 5px; padding: 20px;"
                          >
                            <h1>Welcome, ${sanitizeHtml(firstName)} ${sanitizeHtml(lastName)}</h1>
                            <p>Thank you for creating an account with us.</p>
                            <p>Please verify your email by clicking the button below:</p>
                            <a 
                              href="${verificationLink.toString()}"
                              style="display: inline-block; padding: 12px 24px; background-color: #007bff;
                              color: #ffffff; text-decoration: none; border-radius: 5px; font-weight: bold;"
                            >
                              Verify your Account
                            </a>
                            <p style="margin-top: 15px">If the button doesn't work, copy and paste this link into your browser:</p>
                            <p style="word-break: break-all;>
                              <a href="${verificationLink.toString()}" style="color: #007bff;">${verificationLink.toString()}</a>
                            </p>
                            <p>This link will expire in 24 hours.</p>
                            <p>If you did not create this account, please ignore this email.</p>
                            <hr style="border-top: 1px solid #e0e0e0; margin: 20px 0;">
                            <p>© ${new Date().getFullYear()} SmartKlean Cleaning Services. All rights reserved.</p>
                          </div>
                        </body>
                      </html>
                    `,
                });

                logger.info(`Verification email sent to ${maskEmail(email)}`);

            } catch (emailError) {
                logger.error(`Failed to send verification email to ${maskEmail(email)}: ${emailError.message}`);
                return res.status(200).json({
                    status: 'success',
                    message: 'Account created successfully, but failed to send verification email. Please contact support.',
                });
            }

            return res.status(200).json({
                status: 'success',
                message: 'Account created successfully, Please check your email to verify your account.',
            });

            // Catches any generic errors during the signup process (e.g., database issues, network issues).
        } catch (error) {
            logger.error(`Signup request error: ${error.message}`);
            return handleGenericErrors(error, res, 'signup');
        }
    }
];

// Verify user middleware
exports.getVerifyEmail = async (req, res) => {
    try {
        const { token } = req.query;

        if (!token) {
            logger.warn('No verification token provided');
            return res.status(400).json({
                status: 'error',
                message: 'Invalid verification link',
                resend: true,
            });
        }

        // Verify JWT token
        let decoded;
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET);
        } catch (jwtError) {
            logger.warn(`Invalid or expired JWT token: ${token}`);
            return res.status(400).json({
                status: 'error',
                message: 'Invalid or expired verification token. Please request a new verification link.',
                resend: true
            });
        }

        // Find user by verification token and check expiration
        const user = await User.findOne({
            email: decoded.email,
            verificationToken: token,
            verificationTokenExpires: { $gt: new Date() },    // Check if token is not expired
        });

        if (!user) {
            logger.warn(`User not found or token expired for email: ${maskEmail(decoded.email)}`);
            return res.status(400).json({
                status: 'error',
                message: 'Invalid or expired verification token. Please request a new verification email link.',
                resend: true,                 // Indicate resend option
            });
        }

        // Mark user as verified
        user.isVerified = true;
        user.verificationToken = null;          // Clear token
        user.verificationTokenExpires = null;  // Clear token expiration
        await user.save();

        logger.info(`User verified: ${maskEmail(user.email)}`);
        return res.status(200).json({
            status: 'success',
            message: 'Email verified successfully. You can now proceed to log in.'
        });
    } catch (error) {
        logger.error(`Verify email request error: ${error.message}`);
        return handleGenericErrors(error, res, 'email verification');
    }
};

// Resend verification email
exports.postResendVerificationEmail = [
    requestRateLimiter(5, '/auth/resend-verification', 'resend attempts'),
    sanitizeInputs,
    validateResend,
    handleValidationErrors,
    async (req, res) => {
        try {
            const { token } = req.body;

            // Find user by verification token (But at this point it is expired)
            const user = await User.findOne({ verificationToken: token });
            if (!user) {
                logger.warn(`Resend email verification attempt with invalid token: ${token}`);
                return res.status(404).json({
                    status: 'error',
                    message: 'Invalid verification token',
                });
            }

            // Check if user is already verified
            if (user.isVerified) {
                logger.info(`Resend verification attempt for already verified user: ${maskEmail(user.email)}`);
                return res.status(400).json({
                    status: 'error',
                    message: 'Account already verified',
                });
            }

            // Generate new verification token
            const newVerificationToken = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { 
                expiresIn: '24h',
                issuer: process.env.JWT_ISSUER,
                audience: process.env.JWT_AUDIENCE, 
            });
            const tokenExpiration = new Date(Date.now() + 24 * 60 * 60 * 1000);  // Token expires in 24 hours

            user.verificationToken = newVerificationToken;
            user.verificationTokenExpires = tokenExpiration;
            await user.save();

            // Resend new verification email
            try {
                const verificationLink = `${process.env.FRONTEND_URL}/verify?token=${newVerificationToken}`;

                await sendEmail({
                    to: email,  // User's email
                    subject: 'Verify your Account - SmartKlean Cleaning Services!',
                    html: `
                      <!DOCTYPE html>
                      <html lang="en">
                        <head>
                          <meta charset="UTF-8">
                          <meta name="viewport" content="width=device-width, initial-scale=1.0">
                          <title>Account Verification</title>
                        </head>
                        <body 
                          style="font-family: Arial, sans-serif;
                          color: #333; margin: 0; padding: 20px;"
                        > 
                          <div 
                            style="max-width: 600px; margin: auto;
                            border: 1px solid #e0e0e0; border-radius: 5px; padding: 20px;"
                          >
                            <h1>Hello, ${sanitizeHtml(firstName)} ${sanitizeHtml(lastName)}</h1>
                            <p>We received a request to resend your verification email.</p>
                            <p>Please verify your email by clicking the button below:</p>
                            <a 
                              href="${verificationLink.toString()}"
                              style="display: inline-block; padding: 12px 24px; background-color: #007bff;
                              color: #ffffff; text-decoration: none; border-radius: 5px; font-weight: bold;"
                            >
                              Verify your Account
                            </a>
                            <p style="margin-top: 15px">If the button doesn't work, copy and paste this link into your browser:</p>
                            <p style="word-break: break-all;>
                              <a href="${verificationLink.toString()}" style="color: #007bff;">${verificationLink.toString()}</a>
                            </p>
                            <p>This link will expire in 24 hours.</p>
                            <p>If you did not request this, please ignore this email.</p>
                            <hr style="border-top: 1px solid #e0e0e0; margin: 20px 0;">
                            <p>© ${new Date().getFullYear()} SmartKlean Cleaning Services. All rights reserved.</p>
                          </div>
                        </body>
                      </html>
                    `,
                });

                logger.info(`Resend verification email sent to ${maskEmail(user.email)}`);

            } catch (emailError) {
                logger.error(`Failed to send resend verification email to ${maskEmail(user.email)}: ${emailError.message}`);
                return res.status(500).json({
                    status: 'error',
                    message: 'Failed to send resend verification email. Please contact support.',
                });
            }

            return res.status(200).json({
                status: 'success',
                message: 'Verification email resent successfully. Please check your email.'
            });

        } catch (error) {
            logger.error(`Resend verification email request error: ${error.message}`);
            return handleGenericErrors(error, res, 'resendVerification');
        }
    }
];

