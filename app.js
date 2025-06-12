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
const { storeCsrfToken, getCsrfToken } = require('./utils/redis.js');
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
    origin: process.env.FRONTEND_URL,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-csrf-token'],
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

// CSRF protection
const csrfProtection = async (req, res, next) => {
  const sessionId = getSessionIdentifier(req, res);

  // Skip CSRF check for safe methods
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  // Check CSRF token for protected methods (POST, PUT, DELETE, etc.)
  const csrfToken = req.body._csrf || req.headers['x-csrf-token'];
  const storedToken = await getCsrfToken(sessionId);

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
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
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
app.get('/csrf-token', async (req, res) => {
try {
    const csrfToken = generateCsrfToken();
    const sessionId = getSessionIdentifier(req, res);

    // Store token in Redis with 1-hour expiration
    await storeCsrfToken(sessionId, csrfToken);

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
