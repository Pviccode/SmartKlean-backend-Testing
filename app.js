// Built-in or third-party modules
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const cors = require('cors');  
const crypto = require('crypto');   
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

// Custom modules
const verifyJwtToken = require('./utils/jwtVerify.js');
const connectDB = require('./config/db.js');
const authRoutes = require('./routes/authRoutes.js');
const bookingRoutes = require('./routes/bookingRoutes.js');
const errorHandler = require('./controllers/errorController.js');

// Initialize app
const app = express();

// Built-in middlewares
app.use(helmet());     
app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: 'http://localhost:5173',
    credentials: true,
  }
));

// Custom CSRF middleware
const generateCsrfToken = () => {
  return crypto.randomBytes(32).toString('hex');      // Generate a secure random token
};

const getSessionIdentifier = (req, res) => {
  console.log('Cookies in getSessionIdentifier', req.cookies);
  if (!req.cookies) {
    console.error('req.cookies is undefined');
    return crypto.randomUUID();
  }

  // Extract user ID from JWT if available
  const token = req.cookies?.auth_token;
  if (token) {
    const { isValid, decoded } = verifyJwtToken(token);
    if (isValid && decoded?.id) {
      return decoded.id;          // Authenticated user ID
    }
  }

  // For unauthenticated users, use or generate a unique session ID
  let sessionId = req.cookies?.session_id;
  if (!sessionId) {
    sessionId = crypto.randomUUID();   // Generate UUID using crypto
    req.res.cookie('session_id', sessionId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", 
      sameSite: 'strict'
    });
  };
  return sessionId;
};

// Store CSRF tokens in memory (replace with Redis or DB for production)
const csrfTokens = new Map();

// CSRF protection
const csrfProtection = (req, res, next) => {
  const sessionId = getSessionIdentifier(req, res);

  // Skip CSRF check for safe methods
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  // Check CSRF token for protected methods (POST, PUT, DELETE, etc.)
  const csrfToken = req.body._csrf || req.headers['x-csrf-token'];
  const storedToken = csrfTokens.get(sessionId);

  if (!csrfToken || csrfToken !== storedToken) {
    console.error('CSRF token validation failed:', { csrfToken, storedToken });
    return res.status(403).json({
      status: 'error',
      message: 'Invalid CSRF token'
    });
  }

  // Token is valid, proceed
  next();
}

app.use((req, res, next) => {               // Apply CSRF protection to routes that need it (e.g., POST, PUT, DELETE)
  if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
    csrfProtection(req, res, next);
  } else {
    next();
  }
});

// Enforce HTTPS in production
if (process.env.NODE_ENV === 'production') {
    app.use((req, res, next) => {
      if (req.header('x-forwarded-proto') !== 'https') {
        res.redirect(`https://${req.header('host')}${req.url}`);
      } else {
        next();
      }
    });
}

// Route to expose CSRF token to frontend
app.get('/csrf-token', (req, res) => {
try {
    const csrfToken = generateCsrfToken();
    const sessionId = getSessionIdentifier(req, res);

    // Store token associated with session ID
    csrfTokens.set(sessionId, csrfToken);
    console.log('CSRF Token:', csrfToken);

    // Set CSRF token as cookie
    res.cookie('_csrf', csrfToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });

    console.log('Generated CSRF Token:', csrfToken, 'for Session ID:', sessionId);
    return res.json({ csrfToken });
  } catch (err) {
    console.error('CSRF Token generation Error:', err);
    res.status(500).json({ 
      status: 'error',
      message: 'Failed to generate CSRF token' 
    });
  }
});

// MongoDB connection
connectDB();

// Routes
app.use('/auth', authRoutes);
app.use('/bookings', bookingRoutes);

// Error handling
// app.use(errorHandler);
const PORT = process.env.PORT;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
});
