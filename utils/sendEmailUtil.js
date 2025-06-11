const sgMail = require('@sendgrid/mail');
const nodemailer = require('nodemailer');

const logger = require('../config/logger.js');

if (!process.env.SENDGRID_API_KEY || !process.env.SENDGRID_SENDER_EMAIL) {
    logger.error('Missing SENDGRID_API_KEY, or SENDGRID_SENDER_EMAIL in environment variables');
    process.exit(1);
}

// Set SendGrid API key
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// Create Nodemailer transporter using SendGrid
const transporter = nodemailer.createTransport({
    service: 'SendGrid',    // SendGrid is used as the email service
    auth: {
        user: 'apikey',  // SendGrid requires 'apikey' as the username
        pass: process.env.SENDGRID_API_KEY,
    }
});

const sendEmail = async ({to, subject, html}) => {
    // Define email options
    const mailOptions = {
        from: process.env.SENDGRID_SENDER_EMAIL,  // Your verified sender email from SendGrid
        to,
        subject,
        html,
    }
    return transporter.sendMail(mailOptions);
};

module.exports = sendEmail;