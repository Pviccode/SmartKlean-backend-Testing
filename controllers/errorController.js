const errorHandler = (err, req, res, next) => {
    console.error(err.stack);
    if (err.message.includes('Invalid CSRF token')) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    res.status(err.status || 500).json({
        message: process.env.NODE_ENV === 'production' ? 'Internal Server Error' : err.message,
    });
};