require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// Middleware
app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true
}));
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// Models
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['DONOR', 'RECEIVER', 'ADMIN'], required: true },
  bloodType: { type: String, enum: ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-'] },
  location: { type: String },
  lastDonationDate: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

const bloodRequestSchema = new mongoose.Schema({
  patientName: { type: String, required: true },
  hospital: { type: String, required: true },
  bloodType: { type: String, required: true, enum: ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-'] },
  unitsRequired: { type: Number, required: true, min: 1 },
  urgency: { type: String, enum: ['Normal', 'Urgent', 'Emergency'], default: 'Normal' },
  contactNumber: { type: String, required: true },
  location: { type: String, required: true },
  additionalInfo: { type: String },
  requester: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  donor: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  status: { type: String, enum: ['PENDING', 'APPROVED', 'REJECTED', 'COMPLETED'], default: 'PENDING' },
  createdAt: { type: Date, default: Date.now }
});

const notificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  message: { type: String, required: true },
  type: { type: String, enum: ['DONATION_OFFER', 'REQUEST_UPDATE', 'SYSTEM'], required: true },
  isRead: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const donationSchema = new mongoose.Schema({
  donorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  requestId: { type: mongoose.Schema.Types.ObjectId, ref: 'BloodRequest', required: true },
  unitsDonated: { type: Number, required: true },
  location: { type: String, required: true },
  donationDate: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const BloodRequest = mongoose.model('BloodRequest', bloodRequestSchema);
const Notification = mongoose.model('Notification', notificationSchema);
const Donation = mongoose.model('Donation', donationSchema);

// Auth Middleware
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) throw new Error('Please authenticate');

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) throw new Error('User not found');

    req.user = user;
    req.token = token;
    next();
  } catch (err) {
    res.status(401).json({ message: err.message });
  }
};

const adminAuth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) throw new Error('Please authenticate');

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user || user.role !== 'ADMIN') throw new Error('Admin access required');

    req.user = user;
    req.token = token;
    next();
  } catch (err) {
    res.status(403).json({ message: err.message });
  }
};

// Routes

// Health Check
app.get('/', (req, res) => {
  res.send('BloodLink Server is running');
});

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role, bloodType, location } = req.body;

    if (!name || !email || !password || !role) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    if (!['DONOR', 'RECEIVER'].includes(role)) {
      return res.status(400).json({ message: 'Invalid role' });
    }

    if (role === 'DONOR' && !bloodType) {
      return res.status(400).json({ message: 'Blood type is required for donors' });
    }

    if (role === 'DONOR' && !location) {
      return res.status(400).json({ message: 'Location is required for donors' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already in use' });
    }

    const user = new User({
      name,
      email,
      password: await bcrypt.hash(password, 10),
      role,
      bloodType: role === 'DONOR' ? bloodType : undefined,
      location: role === 'DONOR' ? location : undefined
    });

    await user.save();
    
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ user, token });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ user, token });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/auth/me', auth, async (req, res) => {
  res.json(req.user);
});

// User Routes
app.put('/api/users/profile', auth, async (req, res) => {
  try {
    const updates = Object.keys(req.body);
    const allowedUpdates = ['name', 'location', 'lastDonationDate'];
    const isValidOperation = updates.every(update => allowedUpdates.includes(update));

    if (!isValidOperation) {
      return res.status(400).json({ message: 'Invalid updates' });
    }

    updates.forEach(update => {
      if (update === 'lastDonationDate' && req.body[update]) {
        req.user[update] = new Date(req.body[update]);
      } else {
        req.user[update] = req.body[update];
      }
    });

    await req.user.save();
    res.json(req.user);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/users', adminAuth, async (req, res) => {
  try {
    const users = await User.find({}, { password: 0 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/users/:id', adminAuth, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Delete associated data
    await BloodRequest.deleteMany({ $or: [{ requester: user._id }, { donor: user._id }] });
    await Notification.deleteMany({ userId: user._id });
    await Donation.deleteMany({ donorId: user._id });

    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Donation Routes
app.get('/api/donations/:donorId', auth, async (req, res) => {
  try {
    if (req.user._id.toString() !== req.params.donorId && req.user.role !== 'ADMIN') {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    const donations = await Donation.find({ donorId: req.params.donorId })
      .populate('requestId', 'patientName hospital')
      .sort({ donationDate: -1 });
      
    res.json(donations);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Blood Request Routes
app.post('/api/requests', auth, async (req, res) => {
  try {
    if (req.user.role !== 'RECEIVER') {
      return res.status(403).json({ message: 'Only receivers can create requests' });
    }

    const { patientName, hospital, bloodType, unitsRequired, urgency, contactNumber, location, additionalInfo } = req.body;

    const request = new BloodRequest({
      patientName,
      hospital,
      bloodType,
      unitsRequired,
      urgency,
      contactNumber,
      location,
      additionalInfo,
      requester: req.user._id
    });

    await request.save();
    res.status(201).json(request);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/requests', auth, async (req, res) => {
  try {
    let query = {};
    
    if (req.user.role === 'DONOR' && req.user.bloodType) {
      query.bloodType = req.user.bloodType;
      query.status = 'APPROVED';
      
      if (req.user.location) {
        query.location = req.user.location;
      }
    }
    
    const requests = await BloodRequest.find(query)
      .populate('requester', 'name email')
      .populate('donor', 'name email')
      .sort({ createdAt: -1 });
    res.json(requests);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/requests/user', auth, async (req, res) => {
  try {
    const requests = await BloodRequest.find({ requester: req.user._id })
      .populate('donor', 'name email')
      .sort({ createdAt: -1 });
    res.json(requests);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/requests/all', adminAuth, async (req, res) => {
  try {
    const requests = await BloodRequest.find()
      .populate('requester', 'name email')
      .populate('donor', 'name email')
      .sort({ createdAt: -1 });
    res.json(requests);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/requests/:id', auth, async (req, res) => {
  try {
    if (req.user.role !== 'ADMIN') {
      return res.status(403).json({ message: 'Only admins can update requests' });
    }

    const { status } = req.body;
    const request = await BloodRequest.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    ).populate('requester', 'name email');

    if (!request) {
      return res.status(404).json({ message: 'Request not found' });
    }

    // Create notification for requester
    if (status === 'APPROVED' || status === 'REJECTED' || status === 'COMPLETED') {
      const notification = new Notification({
        userId: request.requester._id,
        title: 'Request Update',
        message: `Your blood request for ${request.patientName} has been ${status.toLowerCase()}`,
        type: 'REQUEST_UPDATE'
      });
      await notification.save();
    }

    res.json(request);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/requests/:id', auth, async (req, res) => {
  try {
    const request = await BloodRequest.findOneAndDelete({
      _id: req.params.id,
      requester: req.user._id,
      status: 'PENDING'
    });

    if (!request) {
      return res.status(404).json({ message: 'Request not found or cannot be deleted' });
    }

    res.json({ message: 'Request deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/requests/admin/:id', adminAuth, async (req, res) => {
  try {
    const request = await BloodRequest.findByIdAndDelete(req.params.id);
    if (!request) {
      return res.status(404).json({ message: 'Request not found' });
    }

    res.json({ message: 'Request deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/requests/:id/donate', auth, async (req, res) => {
  try {
    if (req.user.role !== 'DONOR') {
      return res.status(403).json({ message: 'Only donors can donate' });
    }

    const request = await BloodRequest.findById(req.params.id);
    if (!request) {
      return res.status(404).json({ message: 'Request not found' });
    }

    if (request.bloodType !== req.user.bloodType) {
      return res.status(400).json({ message: 'Blood type mismatch' });
    }

    // Update request status
    request.donor = req.user._id;
    request.status = 'COMPLETED';
    await request.save();

    // Create donation record
    const donation = new Donation({
      donorId: req.user._id,
      requestId: request._id,
      unitsDonated: request.unitsRequired,
      location: request.location || req.user.location,
      donationDate: new Date()
    });
    await donation.save();

    // Update donor's last donation date
    await User.findByIdAndUpdate(req.user._id, { 
      lastDonationDate: new Date() 
    });

    // Create notification for requester
    const notification = new Notification({
      userId: request.requester,
      title: 'Donation Completed',
      message: `${req.user.name} has completed the donation for ${request.patientName}`,
      type: 'DONATION_COMPLETE'
    });
    await notification.save();

    res.json({ message: 'Donation recorded successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Notification Routes
app.get('/api/notifications/user/:userId', auth, async (req, res) => {
  try {
    if (req.user._id.toString() !== req.params.userId) {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    const notifications = await Notification.find({ userId: req.params.userId })
      .sort({ createdAt: -1 })
      .limit(20);
    res.json(notifications);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/notifications', auth, async (req, res) => {
  try {
    const { userId, title, message, type } = req.body;

    const notification = new Notification({
      userId,
      title,
      message,
      type
    });

    await notification.save();
    res.status(201).json(notification);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.patch('/api/notifications/:id/read', auth, async (req, res) => {
  try {
    const notification = await Notification.findOneAndUpdate(
      { _id: req.params.id, userId: req.user._id },
      { isRead: true },
      { new: true }
    );

    if (!notification) {
      return res.status(404).json({ message: 'Notification not found' });
    }

    res.json(notification);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Stats Route
app.get('/api/stats', adminAuth, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalDonors = await User.countDocuments({ role: 'DONOR' });
    const totalReceivers = await User.countDocuments({ role: 'RECEIVER' });
    const totalRequests = await BloodRequest.countDocuments();
    const completedRequests = await BloodRequest.countDocuments({ status: 'COMPLETED' });

    res.json({
      totalUsers,
      totalDonors,
      totalReceivers,
      totalRequests,
      completedRequests
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Create initial admin
const createInitialAdmin = async () => {
  try {
    const adminExists = await User.findOne({ role: 'ADMIN' });
    if (!adminExists) {
      const admin = new User({
        name: 'Admin',
        email: 'admin@bloodlink.com',
        password: await bcrypt.hash('admin123', 10),
        role: 'ADMIN'
      });
      await admin.save();
      console.log('Initial admin user created');
    }
  } catch (err) {
    console.error('Error creating admin:', err);
  }
};

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);
  await createInitialAdmin();
});