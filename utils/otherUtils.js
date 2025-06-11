// Mask(partially hide part of) email for logging purposes to avoid exposing sensitive user information
const maskEmail = (email) => {
  const [localPart, domain] = email.split('@');
  if (localPart.length <= 4) {
    return `${localPart[0]}***@${domain}`; // Handle short emails
  }
  return `${localPart.slice(0, 3)}***${localPart.slice(-1)}@${domain}`;
};

// Minimal user data formatter
const formatUserResponse = (user) => (
    {
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        createdAt: user.createdAt,
    }
);

module.exports = { maskEmail, formatUserResponse };