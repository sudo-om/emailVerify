const express = require('express')
const jwt = require('jsonwebtoken')
const nodemailer = require('nodemailer')
require('dotenv').config();
const port = process.env.PORT || 3000;
const bcrypt = require('bcryptjs')
const mongo_url = process.env.MONGO_URL
const app = express();
const mongoose =  require('mongoose')

mongoose.connect(mongo_url)

const User = mongoose.model('users', { 
    email: String,
    password: String,
    verified : Boolean 
 });

app.use(express.json());

app.post('/register', async (req, res) => {
    try {
        const username = req.body.username.toLowerCase();
        const password = req.body.password;

        if (!username || !password) {
            return res.status(400).send({ message: 'Username and password are required.' });
        }

        const existingUser = await User.findOne({ email: username });
        if (existingUser) {
            return res.status(400).send("Username already exists");
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({
            email: username,
            password: hashedPassword,
            verified: false
        });

        await user.save();

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        const baseUrl = process.env.BASE_URL || 'http://localhost:3000';

        let transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL,
                pass: process.env.PASSWORD,
            },
        });

        let mailOptions = {
            from: process.env.EMAIL,
            to: username,
            subject: 'Email Verification',
            html: `<p>Click the link to verify your email: 
                   <a href="${baseUrl}/verify-email?token=${token}">Verify Email</a></p>`,
        };

        transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
                console.error('Error sending email:', err);
                return res.status(500).send({ message: 'Error sending email' });
            }
            res.status(200).send({ message: 'User created successfully. Verification email sent!' });
        });

    } catch (error) {
        console.error('Error in registration:', error);
        res.status(500).send({ message: 'Internal server error' });
    }
});


app.get('/verify-email', async (req, res) => {
    const { token } = req.query;

    try {
        // Verify JWT token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decoded.userId;

        // Update the user's verified status
        await User.findByIdAndUpdate(userId, { verified: true });

        res.status(200).send({ message: 'Email successfully verified!' });
    } catch (error) {
        res.status(400).send({ message: 'Invalid or expired token' });
    }
});




app.listen(port,()=>{
    console.log(`Server is running on http://localhost:${port}`);
})
