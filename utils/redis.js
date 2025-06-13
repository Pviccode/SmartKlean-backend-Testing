const redis = require('redis');

// Initialize Redis client
const redisClient = redis.createClient({
  url: process.env.REDIS_URL
});

redisClient.on('error', (err) => console.error('Redis Client Error:', err));
redisClient.on('connect', () => console.log('Connected to Redis'));
redisClient.connect();   // Connect to Redis

const storeCsrfToken = async (sessionId, token) => {
  await redisClient.set(`csrf:${sessionId}`, token, { expiration: 3600 });
};

const getCsrfToken = async (sessionId) => {
  return await redisClient.get(`csrf:${sessionId}`);
};

module.exports = { storeCsrfToken, getCsrfToken };