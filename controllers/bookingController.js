const { body } = require('express-validator');

const Booking = require('../models/Booking.js');
const { sanitizeInputs, handleValidationErrors, handleGenericErrors } = require('../auth/auth-security.js');
const { validateEmail, formatUserResponse} = require('../utils/validation');
const logger = require('../config/logger.js');

// Input validation middleware
const validateBooking = [
    validateEmail,
    body('phoneNumber')
      .trim()
      .notEmpty()
      .withMessage('Phone number is required')
      .matches(/^\+?\d{10,15}$/)
      .withMessage('Phone number must be 10-15 digits.'),
    body('serviceAddress.street')
      .trim()
      .notEmpty()
      .withMessage('Street address is required')
      .isLength({ min: 5, max: 100 })
      .withMessage('Street address must be between 5-100 characters long.'),
    body('serviceAddress.city')
      .trim()
      .notEmpty()
      .withMessage('City is required')
      .isLength({ min: 2, max: 50 })
      .withMessage('City must be between 2-50 characters long.'),
    body('serviceAddress.zip')
      .trim()
      .notEmpty()
      .withMessage('Zip code is required')
      .matches(/^\+?\d{5}(-\d{4})?$/)
      .withMessage('Invalid zip code format'),
    body('services')
      .isArray({ min: 1 })
      .withMessage('At least one service must be selected'),
    body('services.*')
      .isIn([
        'residential_cleaning',
        'construction_cleaning',
        'carpet_cleaning',
        'laundry_cleaning'
      ])
      .withMessage('Invalid service type'),
    body('selectedDate')
      .isISO8601()
      .toDate()
      .custom(value => {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        return value >= today;
      })
      .withMessage('Service date must be today or in the future'),
    body('notes')
      .optional()
      .isLength({ max: 500 })
      .withMessage('Notes must be less than 500 characters.')
];

// Place a new booking (user). 
exports.postBooking = [
    sanitizeInputs,
    validateBooking,
    handleValidationErrors,
    async (req, res) => {
        // Restricts this endpoint to users with the role of 'user' (not 'admin'). Therefore, ensures only regular users can make bookings, preventing admins from using this endpoint (admins might have a separate process).
        if (req.user.role !== 'user') {
          return res.status(403).json({ msg: 'Access denied' });
        }

        try {
          const bookingData = {
            user: req.user.id,        // Sets the user field to the authenticated user’s _id (from the JWT), linking the booking to the user.
            ...req.body
          }
          // Create a new booking document
          const booking = new Booking(bookingData);
          await booking.save();    // Saves the booking document to the MongoDB bookings collection.

          console.log('booking created', booking);
          logger.info(`Booking created by user ${req.user.id}`, { bookingId: booking._id });
          res.status(201).json({
            message: 'Booking created successfully',
            booking            // Sends the saved booking document as a JSON response with a default 200 OK status.
          });

        // Catches any errors during the try block (e.g., validation errors, database issues).
        } catch (error) {
          return handleGenericErrors(error, res, 'booking creation');
        }
    }
];


// Update an already existing booking (user)
exports.patchBooking = [
    sanitizeInputs,
    validateBooking,
    handleValidationErrors,
    async (req, res) => {
        try {
            const booking = await Booking.findById(req.params.bookingId);
            if (!booking) {
                return res.status(404).json({ message: 'Booking not found' })
            }

            // Ensure the user can only update their own booking
            if (booking.user.toString() !== req.user.id) {
                return res.status(403).json({
                    message: 'Unauthorized to update this booking.'
                });
            }

            Object.assign(booking, req.body);    // Merges req.body properties into the existing booking document, overwriting existing fields
            await booking.save();

            res.status(200).json({
                message: 'Booking updated successfully',
                booking
            });
        } catch (error) {
            return handleGenericErrors(error, res, 'booking update');
        }
    }
];

// Retrieves all bookings belonging to the authenticated user (user)
exports.getUserBookings = async (req, res) => {
    if (req.user.role !== 'user') {
        return res.status(403).json({ msg: 'Access denied' });
    }

    try {
        // Finds all Booking documents where the user field matches the authenticated user’s _id (req.user.id).
        // Mongoose find() queries the bookings collection with the filter { user: req.user.id }. 
        // .populate('user', 'name email'): Replaces the user field’s ObjectId with the corresponding User document, including only the name and email fields.
        // Example: Instead of user: "507f191e810c19729de860ea", you get user: { name: "John Doe", email: "john.doe@example.com" }.
        const bookings = await Booking.find({ user: req.user.id }).populate('user', 'name email');  
        res.json(bookings);      // Sends the array of bookings as a JSON response with a 200 OK status.

    // Catches errors (e.g., database connection issues, invalid ObjectId).
    } catch (error) {
        console.error(error);
        res.status(500).json({ msg: 'Server error' });
    }
};

exports.getBookingById = async (req, res) => {
    if (req.user.role !== 'user') {
        return res.status(403).json({ msg: 'Access denied' });
    }

    try {
        const booking = await Booking.findById(req.params.bookingId).select('-user -__v');

        console.log('seen', booking);
        if (!booking) {
            return res.status(404).json({ msg: 'Booking not found.' });
        }
        res.json(booking);
    } catch (error) {
        console.error('Error fetching booking:', error);
        res.status(500).json({ msg: 'Server error' });
    }
};

// Retrieves all bookings in the system, typically for admin users to manage and monitor bookings.
exports.getAllBookings = async (req, res) => {

    try {
        // Finds all Booking documents in the bookings collection (no filter, so it returns everything). Then populates the user field with name and email from the User collection.
        const bookings = await Booking.find().populate('user', 'name email');
        res.json(bookings);        // Sends the array of all the bookings of all users as a JSON response with a 200 OK status.
    } catch (error) {
        console.error(error);
        res.status(500).json({ msg: 'Server error' });
    }
};

// Allows an admin to update the status of an existing booking (e.g., from 'Pending' to 'Processing' or 'Delivered'). Then returns the updated booking.
exports.putBookingStatus = async (req, res) => {
    const { status } = req.body;

    try {
        // Finds the booking document by its _id, passed as a URL parameter (req.params.id).
        const booking = await Booking.findById(req.params.id);
        // If no booking is found, returns a 404 Not Found with { msg: 'Booking not found.' }.
        if (!booking) {
            return res.status(404).json({ msg: 'Booking not found.' });
        }

        // Updates the status field of the booking document to the new value from req.body.
        booking.status = status;
        await booking.save();  // Saves the updated booking document to the database.
        res.json(booking);     // Sends the updated booking as a JSON response with a 200 OK status.
    } catch (error) {
        console.error(error);
        res.status(500).json({ msg: 'Server error' });
    }
};