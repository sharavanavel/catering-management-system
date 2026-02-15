const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'frontend')));

const MONGO_URI = 'mongodb+srv://shara_31:Vel@cluster0.bg9berl.mongodb.net/?appName=Cluster0';
const JWT_SECRET = 'cater_secret_123';

mongoose.connect(MONGO_URI).then(() => console.log('✅ MongoDB Connected'));

// SCHEMAS
const User = mongoose.model('User', new mongoose.Schema({
    name: String, email: { type: String, unique: true }, password: String
}));

const Event = mongoose.model('Event', new mongoose.Schema({
    functionName: String, date: String, amount: Number,
    totalMembersNeeded: Number, membersRegistered: { type: Number, default: 0 },
    location: String, createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}));

// NODEMAILER CONFIG
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'sharavanavelj@gmail.com',
        pass: 'osxt kvtt qopg aptb' 
    }
});

// AUTH MIDDLEWARE
function auth(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).send();
    try { req.user = jwt.verify(token, JWT_SECRET); next(); } catch { res.status(401).send(); }
}

// ROUTES
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const hash = await bcrypt.hash(password, 10);
        const user = await new User({ name, email, password: hash }).save();
        const token = jwt.sign({ id: user._id, name: user.name, email: user.email }, JWT_SECRET);
        res.json({ token, user: { name: user.name, email: user.email } });
    } catch (err) { res.status(400).json({ message: "User exists" }); }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ id: user._id, name: user.name, email: user.email }, JWT_SECRET);
        return res.json({ token, user: { name: user.name, email: user.email } });
    }
    res.status(401).json({ message: 'Invalid' });
});

app.get('/api/events', auth, async (req, res) => res.json(await Event.find().sort({_id:-1})));
app.post('/api/events', auth, async (req, res) => {
    const ev = await new Event({ ...req.body, createdBy: req.user.id }).save();
    res.json(ev);
});

// REGISTER WITH SLOTS CHECK & FULL MAIL DETAILS
app.patch('/api/events/:id/register', auth, async (req, res) => {
    try {
        const { members } = req.body;
        const event = await Event.findById(req.params.id).populate('createdBy');
        if (!event) return res.status(404).send();

        // 1. Availability Check
        const available = event.totalMembersNeeded - event.membersRegistered;
        if (Number(members) > available) {
            return res.status(400).json({ message: "Slots not available" });
        }

        event.membersRegistered += Number(members);
        await event.save();

        // 2. Confirmation Mail to User
        const userMail = {
            from: 'sharavanavelj@gmail.com',
            to: req.user.email,
            subject: `✅ Registration Confirmed: ${event.functionName}`,
            html: `
                <div style="font-family: sans-serif; border: 1px solid #ddd; padding: 20px; border-radius: 10px;">
                    <h2 style="color: #f43f5e;">Registration Success!</h2>
                    <p><b>Registered Mail ID:</b> ${req.user.email}</p>
                    <hr/>
                    <p><b>Event:</b> ${event.functionName}</p>
                    <p><b>Location:</b> ${event.location}</p>
                    <p><b>Date:</b> ${event.date}</p>
                    <p><b>Pay per Head:</b> ₹${event.amount}</p>
                    <p><b>Members Registered:</b> ${members}</p>
                </div>
            `
        };

        // 3. Alert Mail to Host
        const hostMail = {
            from: 'sharavanavelj@gmail.com',
            to: event.createdBy.email,
            subject: `🔥 New Registration: ${event.functionName}`,
            text: `Hi Admin, User ${req.user.email} has registered ${members} members for your event.`
        };

        transporter.sendMail(userMail);
        transporter.sendMail(hostMail);
        res.json(event);
    } catch (err) { res.status(500).send(err.message); }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));