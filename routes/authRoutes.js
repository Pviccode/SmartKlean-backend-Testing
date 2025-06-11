const express = require('express');

const { auth } = require('../auth/auth-middleware.js');
const signupController = require('../controllers/signupController.js');
const { postLogin, getCurrentUser, postLogout, postRequestPasswordReset, postResetPassword} = require('../controllers/loginController.js');

const router = express.Router();

router.post('/signup', signupController.postSignup);

router.get('/verify-newUser', signupController.getVerifyEmail);

router.post('/resend-verification', signupController.postResendVerificationEmail);

router.post('/login', postLogin);

router.post('/request-password-reset', postRequestPasswordReset);

router.post('/reset-password', postResetPassword);

router.get('/user', auth, getCurrentUser);

router.post('/logout', postLogout);

module.exports = router;