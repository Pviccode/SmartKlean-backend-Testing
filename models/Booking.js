const mongoose = require('mongoose');

// Defines a new Mongoose schema for the Booking collection in the MongoDB database.
const bookingSchema = new mongoose.Schema({
    // Links the booking to a specific user, establishing a relationship between the Booking and User collections.
    user: { 
        type: mongoose.Schema.Types.ObjectId,    // References a MongoDB document's unique identifier (_id) from another collection.
        ref: 'User',                             // Specifies that this ObjectId refers to a document in the User collection (another Mongoose model).
        required: [true, 'A booking must be associated with a user'],                           // Ensures that every Booking document must have a valid user field (i.e., a reference to a User document).
    },

    email: {
        type: String,
        required: [true, 'Email is required'],
        trim: true,
        lowercase: true,
        match: [/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/, 'Invalid email address']
    },

    phoneNumber: {
        type: String,
        required: [true, 'Phone number is required'],
        trim: true,
        validate: {
            validator: (value) => /^\+?\d{10,15}$/.test(value),
            message: 'Phone number must be 10-15 digits, optionally starting with +',
        }
    },

    // Address information
    serviceAddress: {
        street: { 
            type: String, 
            required: [true, 'Street address is required'],   // The required: true ensures that all three fields must be provided.
            trim: true,
            minLength: [5, 'Street address must be at least 5 characters'],
            maxlength: [100, 'Street address must be less than 100 characters']
        },    
        city: { 
            type: String, 
            required: [true, 'City is required'],
            trim: true,
            minlength: [5, 'City must be at least 5 characters'],
            maxlength: [100, 'City must be less than 100 characters']
        },
        zip: { 
            type: String, 
            required: [true, 'Zip code is required'],
            trim: true,
            validate: {
                validator: (value) => /^\+?\d{5}(-\d{4})?$/.test(value),
                message: 'Invalid zip code format',
            }
        }
    },

    // Represents the services requested in the booking (e.g., a booking might include ["residential_cleaning", "laundry_cleaning"]).
    services: [
        { 
            type: String, 
            required: [true, 'At least one service must be selected'], 
            enum: {
                // Restricts the values in the services array to one of the specified options. If a value outside this list is provided, Mongoose will throw a validation error.
                values: [
                    'residential_cleaning', 
                    'construction_cleaning', 
                    'carpet_cleaning', 
                    'laundry_cleaning' 
                ],
                message: 'Invalid service type' 
            },
            validate: {
                validator: (array) => array.length > 0,
                message: 'At least one service must be selected'
            },    
        },
    ],

    // Date of service or work
    selectedDate: { 
        type: Date, 
        required: [true, 'Service date is required'],
        validate: {
            validator: (value) => {
                const today = new Date();
                today.setHours(0, 0, 0, 0);
                return value >= today;
            },
            message: 'Service date must be today or in the future',
        },
    },

    // Additional notes
    notes: {
        type: String,
        trim: true,
        maxlength: [500, 'Notes must be less than 500 characters'],
        default: null,
    },

    // Tracks the current state of the booking (e.g., whether it’s awaiting processing (pending), being processed, or has been delivered).
    status: {
        type: String,
        enum: {
            values: ['Pending', 'Processing', 'Delivered'],
            message: 'Invalid status value'
        },
        default: 'Pending'                              // If no status is provided when creating a booking, it defaults to 'Pending'.
    },

    // Tracks when the booking was created, useful for auditing and sorting bookings by creation time.
    createdAt: {
        type: Date,
        default: Date.now    
    }
});

// Creates a Mongoose model named Booking based on the bookingSchema and exports it for use in other parts of the application.
module.exports = mongoose.model('Booking', bookingSchema);



// Note: By default, Mongoose pluralizes the model name (Booking → bookings) to determine the MongoDB collection name, unless overridden.

// Here’s an example of what a document might look like in the MongoDB bookings collection based on this schema:
// {
//     "_id": "507f1f77bcf86cd799439011",
//     "user": "507f191e810c19729de860ea",
//     "email": "john.doe@example.com",
//     "phoneNumber": "+2348108004169"
//     "serviceAddress": {
//         "street": "123 Main St",
//         "city": "New York",
//         "zip": "10001"
//     },
//     "services": ["residential_cleaning", "carpet_cleaning"],
//     "selectedDate": "2025-04-24T10:00:00Z",
//     "notes": "Please clean the living room thoroughly"
//     "status": "Pending",
//     "createdAt": "2025-04-23T08:15:30Z",
//     "__v": 0
// }