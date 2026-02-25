require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'frontend')));

// MONGODB CONNECTION
// .env file-la MONGO_URI and JWT_SECRET define pannunga
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/caterpro_db';
const JWT_SECRET = process.env.JWT_SECRET || 'cater_secret_123';

mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ MongoDB Connected'))
    .catch(err => console.error('❌ MongoDB Connection Error:', err));

// SCHEMAS
const User = mongoose.model('User', new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String
}));

const Event = mongoose.model('Event', new mongoose.Schema({
    functionName: String,
    date: String,
    amount: Number,
    totalMembersNeeded: Number,
    membersRegistered: { type: Number, default: 0 },
    location: String,
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}));

// NODEMAILER CONFIG
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS
    }
});

// AUTH MIDDLEWARE
function auth(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: "No Token" });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ message: "Invalid Token" });
    }
}

// --- ROUTES ---

// 1. SIGNUP
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const hash = await bcrypt.hash(password, 10);
        const user = await new User({ name, email, password: hash }).save();
        const token = jwt.sign({ id: user._id, name: user.name, email: user.email }, JWT_SECRET);
        res.json({ token, user: { name: user.name, email: user.email } });
    } catch (err) { res.status(400).json({ message: "User exists or Error" }); }
});

// 2. LOGIN
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (user && await bcrypt.compare(password, user.password)) {
            const token = jwt.sign({ id: user._id, name: user.name, email: user.email }, JWT_SECRET);
            return res.json({ token, user: { name: user.name, email: user.email } });
        }
        res.status(401).json({ message: 'Invalid Credentials' });
    } catch (err) { res.status(500).json({ message: "Server Error" }); }
});

// 3. GET ALL EVENTS
app.get('/api/events', auth, async (req, res) => {
    try {
        const events = await Event.find().sort({ _id: -1 });
        res.json(events);
    } catch (err) { res.status(500).json({ message: "Error fetching events" }); }
});

// 4. CREATE EVENT
app.post('/api/events', auth, async (req, res) => {
    try {
        const ev = await new Event({ ...req.body, createdBy: req.user.id }).save();
        res.json(ev);
    } catch (err) { res.status(500).json({ message: "Error creating event" }); }
});

// 5. REGISTER FOR EVENT (Fixed Mail Logic)
app.patch('/api/events/:id/register', auth, async (req, res) => {
    try {
        const { members } = req.body;
        const event = await Event.findById(req.params.id).populate('createdBy');

        if (!event) return res.status(404).json({ message: "Event not found" });

        const available = event.totalMembersNeeded - event.membersRegistered;
        if (Number(members) > available) {
            return res.status(400).json({ message: "Slots not available" });
        }

        // Update Database
        event.membersRegistered += Number(members);
        await event.save();

        // Prepare User Email
        const userMail = {
            from: '"CaterPro" <sharavanavelvarshini@gmail.com>',
            to: req.user.email,
            subject: `✅ Registration Confirmed: ${event.functionName}`,
            html: `
                <div style="font-family: sans-serif; border: 1px solid #ddd; padding: 20px; border-radius: 10px;">
                    <h2 style="color: #f43f5e;">Registration Success!</h2>
                    <p>Hi <b>${req.user.name}</b>,</p>
                    <p>Your registration for the following event is confirmed.</p>
                    <hr/>
                    <p><b>Event:</b> ${event.functionName}</p>
                    <p><b>Location:</b> ${event.location}</p>
                    <p><b>Date:</b> ${event.date}</p>
                    <p><b>Pay per Head:</b> ₹${event.amount}</p>
                    <p><b>Staff Count:</b> ${members}</p>
                </div>
            `
        };

        // Send User Mail Asynchronously
        transporter.sendMail(userMail)
            .then(() => console.log("User mail sent"))
            .catch(e => console.log("User mail error", e));

        // SAFELY Check if the host exists before sending the host email
        if (event.createdBy && event.createdBy.email) {
            const hostMail = {
                from: '"CaterPro Alert" <sharavanavelvarshini@gmail.com>',
                to: event.createdBy.email, // Event create panna admin-uku pogum
                subject: `🔥 New Registration: ${event.functionName}`,
                text: `Hi Admin, User ${req.user.name} (${req.user.email}) has registered ${members} members for your event: ${event.functionName}.`
            };

            transporter.sendMail(hostMail)
                .then(() => console.log("Host mail sent"))
                .catch(e => console.log("Host mail error", e));
        } else {
            console.log("⚠️ Host user not found for this event. Skipping host email notification.");
        }

        // Response immediately send pannalaam, mail backend-la send aagum
        res.json(event);

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Registration failed", error: err.message });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));