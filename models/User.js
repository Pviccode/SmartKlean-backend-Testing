const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const logger = require('../config/logger');
const { EMAIL_REGEX } = require('../utils/validation');

// Defines a new Mongoose schema for the User collection in the MongoDB database.
const userSchema = new mongoose.Schema({
    firstName: { 
        type: String, 
        required: [true, 'First name is required'], 
        trim: true,             
        minlength: [2, 'First name must be at least 2 characters'],
        maxlength: [50, 'First name cannot exceed 50 characters']
    },
    lastName: { 
        type: String, 
        required: [true, 'Last name is required'], 
        trim: true,             
        minlength: [2, 'Last name must be at least 2 characters'],
        maxlength: [50, 'Last name cannot exceed 50 characters']
    },
    email: { 
        type: String, 
        required: [true, 'Email is required'], 
        unique: true,         
        lowercase: true,
        trim: true,
        match: [EMAIL_REGEX, 'Invalid email address'],
        index: true,                                     // Explicitly ensure index for performance
    },
    password: { 
        type: String, 
        required: [true, 'Password is required'],
        select: false,                                                   // Exclude by default from queries      
        minlength: [8, 'Password must be at least 8 characters long'],         
    },
    role: { 
        type: String, 
        enum: {
            values: ['user', 'admin'],
            message: 'Role must be either "user" or "admin"',
        }, 
        default: 'user' 
    },
    createdAt: { 
        type: Date, 
        default: Date.now,
        immutable: true,          // Prevent modification after creation
    },
    lastLogin: {
        type: Date,
        default: null,
    },
    lastFailedLogin: {
        type: Date,
        default: null,
    },
    failedLoginAttempts: {
        type: Number,
        default: 0,
        min: [0, 'Failed login attempts cannot be negative'],
    },
    isVerified: {
        type: Boolean,
        default: false,
    },
    verificationToken: {
        type: String,
        default: null
    },
    verificationTokenExpires: {
        type: Date,
        default: null
    },
    resetPasswordToken: {
        type: String
    },
    resetPasswordExpires: {
        type: Date
    }
});

// Automatically hashes the user’s password before saving the document to the database.
// pre('save') is a Mongoose middleware function that runs before a User document is saved (e.g., during user.save()).
userSchema.pre('save', async function(next) {
    try {
        // Checks whether the password field of the current User document has been modified (changed or newly set) since the document was last saved or created.
        if (this.isModified('password')) {
            const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 10;
            this.password = await bcrypt.hash(this.password, saltRounds);              // If the password field is modified, the plaintext password entered by the user (e.g., "myPassword123") is hashed, and then the password field is updated with the hashed value.
            logger.info(`Password hashed for user: ${this.email}`);
        }
        next();                          // If hashing succeeds, the middleware calls next() to proceed with saving the document.
    } catch (error) {
        logger.error(`Error hashing password for user ${this.email}: ${error.stack}`);
        next(error);  // Handles any errors during hashing and passes them to next(error) to trigger Mongoose’s error handling.
    }
});


// Adds a custom method to the User model for comparing a plaintext password (e.g., from a login attempt) with the stored hashed password.
userSchema.methods.comparePassword = async function(userPassword) {
    try {
        const isMatch = await bcrypt.compare(userPassword, this.password);      // returns true if the passwords match, and false otherwise
        return isMatch;
    } catch (error) {
        logger.error(`Error comparing password for user ${this.email}: ${error.stack}`);
        throw error;                     // Let the calling function (e.g., postLogin) handle the error
    }
};

// Creates a Mongoose model named User based on the userSchema and exports it for use in other parts of the application.
module.exports = mongoose.model('User', userSchema);

