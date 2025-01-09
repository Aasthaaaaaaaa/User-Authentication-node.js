const express = require('express');
const User = require('../models/User');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const router = express.Router();
var jwt = require('jsonwebtoken');
require('dotenv').config();
const fetchuser = require('../middleware/fetchuser')

const JWTSecret = process.env.secret;
const RESET_TOKEN_SECRET = process.env.reset_secret; 


// Create user with help of username email and password <3
router.post('/createuser', [
    body('username', 'Username must have 3 characters').isLength({ min: 3 }),
    body('email', 'Enter a valid email').isEmail(),
    body('password', 'Password must have 5 characters').isLength({ min: 5 }),
], async (req, res) => {

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    // Check if user with the same username or email already exists
    const existingUser = await User.findOne({ $or: [{ username: req.body.username }, { email: req.body.email }] });
    if (existingUser) {
        return res.status(400).json({ error: 'Username or email already exists' });
    }
    // Generating a salt and Hashing the password
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(req.body.password, salt);

    // Using jwt for security of my website
    const data = {
        user: {
            id: User.id
        }
    }
    var token = jwt.sign(data, JWTSecret);

    // Create the user
    User.create({
        username: req.body.username,
        email: req.body.email,
        password: hashedPassword, // Save hashed password
    }).then(user => res.json({token}))
        .catch(err => res.status(500).json({ error: 'Error creating user' }));
});

// Creating an end point for user to login using email and password
router.post('/login', [
    body('email', 'Enter a valid email').isEmail(),
    body('password', 'Password cannot be empty').exists(),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    try {
        const { email, password } = req.body;
        const existingUser = await User.findOne({ email });
        if (!existingUser) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        const passwordCompare = await bcrypt.compare(password, existingUser.password);
        if (!passwordCompare) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        const data = {
            user: {
                id: existingUser.id
            }
        }
        const token = jwt.sign(data, JWTSecret);
        res.json({token});
    } catch (error) {
        console.error('Error finding user:', error);
        res.status(500).json({ error: 'Error finding user' });
    }
});

router.post('/forgotpassword', [
    body('email', 'Enter a valid email').isEmail(),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'User with this email does not exist' });
        }

        // Create a password reset token
        const resetToken = jwt.sign({ id: user.id }, RESET_TOKEN_SECRET, { expiresIn: '15m' }); // Token valid for 15 minutes

        // Here, send the resetToken to the user's email
        // For example, you can use nodemailer or any email service provider
        console.log(`Password reset token (send this via email): ${resetToken}`);

        res.json({ message: 'Password reset token generated. Check your email for further instructions.' });
    } catch (error) {
        console.error('Error generating password reset token:', error);
        res.status(500).json({ error: 'Error generating password reset token' });
    }
});

// Reset Password Endpoint
router.post('/resetpassword', [
    body('resetToken', 'Reset token is required').exists(),
    body('newPassword', 'Password must have 5 characters').isLength({ min: 5 }),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { resetToken, newPassword } = req.body;

        // Verify the reset token
        const decoded = jwt.verify(resetToken, RESET_TOKEN_SECRET);
        const userId = decoded.id;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(400).json({ error: 'Invalid reset token' });
        }

        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update the user's password
        user.password = hashedPassword;
        await user.save();

        res.json({ message: 'Password has been reset successfully' });
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ error: 'Error resetting password' });
    }
});

module.exports = router;