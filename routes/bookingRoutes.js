const express = require('express');

const isAuthenticated = require('../auth/auth-middleware.js');
const bookingController = require('../controllers/bookingController.js');

const router = express.Router();

router.post('/', isAuthenticated.auth, bookingController.postBooking);                      // Path to create a new booking (user-only).

router.patch('/:bookingId', isAuthenticated.auth, bookingController.patchBooking);                     // Path to update an already existing booking (user-only)

router.get('/', isAuthenticated.auth, bookingController.getUserBookings);                   // Path to retrieve the authenticated user’s bookings. (user-only)

router.get('/:bookingId', isAuthenticated.auth, bookingController.getBookingById);

router.get('/admin/all', isAuthenticated.requireAdmin, bookingController.getAllBookings);   // Path to retrieve all bookings for all users (admin-only).  

router.put('/admin/:id', isAuthenticated.requireAdmin, bookingController.putBookingStatus);  // Path to update a booking’s status (admin-only). :id is a URL parameter representing the _id of the booking to update (e.g., /orders/507f1f77bcf86cd799439011).

module.exports = router;