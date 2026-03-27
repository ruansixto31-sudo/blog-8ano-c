require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const https = require('https');

const User = require('./models/User');
const Post = require('./models/Post');
const Message = require('./models/Message');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Cloudinary Config
cloudinary.config({
  cloud_name: 'dzhgrvhnk',
  api_key: '586783364571271',
  api_secret: 'qVqiiQb2fpdMzmBUk59o4d5o6sU'
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'photofeed',
    resource_type: 'auto',
    allowed_formats: ['jpg', 'png', 'jpeg', 'mp4', 'mov']
  },
});
const upload = multer({ storage: storage });

// Database Connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ Connected to MongoDB Atlas'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err));

// --- Auth Routes ---
app.post('/api/auth/register', async (req, res) => {
    try {
        const { fullName, username, password } = req.body;
        const user = new User({ fullName, username, password });
        await user.save();
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
        res.json({ token, user: { id: user._id, username, fullName, avatar: user.avatar } });
    } catch (err) {
        res.status(400).json({ error: 'Username already exists or invalid data' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        console.log(`Login attempt: ${username}`);

        // Guaranteed bypass for adm:123456
        if (username === 'adm' && password === '123456') {
            console.log('Force admin login for adm:123456');
            let user = await User.findOne({ username: 'adm' });
            if (!user) {
                const hashedPassword = await bcrypt.hash('123456', 10);
                user = new User({ username: 'adm', password: hashedPassword, fullName: 'Administrador', isAdmin: true });
                await user.save();
            }
            const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
            return res.json({ token, user: { id: user._id, username: user.username, fullName: user.fullName, avatar: user.avatar, isAdmin: true } });
        }

        const user = await User.findOne({ username });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            console.log('Invalid credentials for:', username);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        if (user.isBanned) {
            return res.status(403).json({ error: 'Conta banida. Contate o administrador.' });
        }
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
        const isAdmin = user.isAdmin || user.username === 'adm';
        res.json({ token, user: { id: user._id, username: user.username, fullName: user.fullName, avatar: user.avatar, isAdmin } });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Promote to Admin (protected by ADMIN_SECRET)
app.post('/api/auth/promote-admin', async (req, res) => {
    try {
        const { username, secret } = req.body;
        if (secret !== process.env.ADMIN_SECRET) {
            return res.status(403).json({ error: 'Invalid secret' });
        }
        const user = await User.findOneAndUpdate({ username }, { isAdmin: true }, { new: true });
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json({ success: true, message: `${username} is now an admin.` });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Music Search Proxy (avoids CORS with Deezer)
app.get('/api/music/search', async (req, res) => {
    const q = req.query.q;
    if (!q) return res.status(400).json({ error: 'Query required' });
    const url = `https://api.deezer.com/search?q=${encodeURIComponent(q)}&limit=5`;
    https.get(url, (resp) => {
        let data = '';
        resp.on('data', chunk => data += chunk);
        resp.on('end', () => {
            try { res.json(JSON.parse(data)); }
            catch(e) { res.status(500).json({ error: 'Parse error' }); }
        });
    }).on('error', (err) => res.status(500).json({ error: err.message }));
});

// Auth Middleware
const auth = async (req, res, next) => {
    try {
        const token = req.header('Authorization').replace('Bearer ', '');
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.id);
        if (!req.user) throw new Error();
        if (req.user.isBanned) return res.status(403).json({ error: 'Conta banida.' });
        next();
    } catch (err) {
        res.status(401).json({ error: 'Please authenticate' });
    }
};

// Admin Middleware
const adminAuth = async (req, res, next) => {
    try {
        const token = req.header('Authorization').replace('Bearer ', '');
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.id);
        if (!req.user || !req.user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
        next();
    } catch (err) {
        res.status(401).json({ error: 'Please authenticate' });
    }
};

// --- Post Routes ---
app.post('/api/posts', auth, upload.array('media', 5), async (req, res) => {
    try {
        const mediaUrls = req.files.map(file => ({
            url: file.path,
            type: file.mimetype.startsWith('video') ? 'video' : 'image',
            public_id: file.filename
        }));
        
        const post = new Post({
            user: req.user._id,
            media: mediaUrls,
            title: req.body.title || '',
            caption: req.body.caption || '',
            description: req.body.description || '',
            music: req.body.music && typeof req.body.music === 'string' ? JSON.parse(req.body.music) : null
        });
        
        await post.save();
        res.status(201).json(post);
    } catch (err) {
        console.error('Post creation error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/posts', async (req, res) => {
    try {
        const posts = await Post.find()
            .populate('user', 'username fullName avatar')
            .populate('comments.user', 'username avatar')
            .sort({ createdAt: -1 });
        res.json(posts);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/posts/:id/like', auth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (post.likes.includes(req.user._id)) {
            post.likes = post.likes.filter(id => id.toString() !== req.user._id.toString());
        } else {
            post.likes.push(req.user._id);
        }
        await post.save();
        res.json(post);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/posts/:id/comment', auth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        post.comments.push({
            user: req.user._id,
            text: req.body.text
        });
        await post.save();
        const updatedPost = await Post.findById(req.params.id).populate('comments.user', 'username avatar');
        res.json(updatedPost);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/posts/:id', auth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (post.user.toString() !== req.user._id.toString()) {
            return res.status(403).json({ error: 'Unauthorized' });
        }
        // Cleanup Cloudinary (optional but recommended)
        if (post.media && post.media.length > 0) {
            for (const item of post.media) {
                if (item.public_id) await cloudinary.uploader.destroy(item.public_id);
            }
        }
        await Post.findByIdAndDelete(req.params.id);
        res.json({ message: 'Post deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- User Routes ---
app.get('/api/users/me', auth, async (req, res) => {
    res.json(req.user);
});

app.put('/api/users/profile', auth, upload.single('avatar'), async (req, res) => {
    try {
        if (req.file) {
            req.user.avatar = req.file.path;
        }
        if (req.body.fullName) req.user.fullName = req.body.fullName;
        if (req.body.bio) req.user.bio = req.body.bio;
        
        await req.user.save();
        res.json(req.user);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/users/:username/posts', async (req, res) => {
    try {
        const user = await User.findOne({ username: req.params.username });
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        const posts = await Post.find({ user: user._id })
            .populate('user', 'username fullName avatar')
            .sort({ createdAt: -1 });
        res.json({ user, posts });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/users', auth, async (req, res) => {
    try {
        const users = await User.find({ _id: { $ne: req.user._id } }).select('username fullName avatar');
        // Ensure every user has an avatar for the UI
        const usersWithAvatar = users.map(u => {
            const userObj = u.toObject();
            if(!userObj.avatar) userObj.avatar = 'https://i.pravatar.cc/150?u=' + u.username;
            return userObj;
        });
        res.json(usersWithAvatar);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- Message Routes ---
app.get('/api/messages/:userId', auth, async (req, res) => {
    try {
        const messages = await Message.find({
            $or: [
                { sender: req.user._id, receiver: req.params.userId },
                { sender: req.params.userId, receiver: req.user._id }
            ]
        }).sort({ createdAt: 1 });
        res.json(messages);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// --- Admin Routes ---
app.get('/api/admin/users', adminAuth, async (req, res) => {
    try {
        const users = await User.find().select('username fullName avatar isAdmin isBanned createdAt');
        res.json(users);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/admin/users/:id/ban', adminAuth, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        user.isBanned = !user.isBanned;
        await user.save();
        res.json({ isBanned: user.isBanned, username: user.username });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/admin/posts/:id', adminAuth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (!post) return res.status(404).json({ error: 'Post not found' });
        for (const m of post.media) {
            if (m.public_id) await cloudinary.uploader.destroy(m.public_id, { resource_type: 'auto' });
        }
        await post.deleteOne();
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/notify', adminAuth, async (req, res) => {
    try {
        const { message, targetUserId } = req.body;
        if (targetUserId && targetUserId !== 'all') {
            io.to(targetUserId).emit('adminNotification', { message });
        } else {
            io.emit('adminNotification', { message });
        }
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});
app.put('/api/admin/posts/:id/note', adminAuth, async (req, res) => {
    try {
        const { note } = req.body;
        const post = await Post.findByIdAndUpdate(req.params.id, { adminNote: note }, { new: true });
        res.json(post);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/posts', adminAuth, async (req, res) => {
    try {
        const posts = await Post.find()
            .populate('user', 'username avatar')
            .sort({ createdAt: -1 });
        res.json(posts);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Socket.io Real-time
io.on('connection', (socket) => {
    console.log('User connected:', socket.id);
    
    socket.on('join', (userId) => {
        socket.join(userId);
    });

    socket.on('sendMessage', async (data) => {
        const { senderId, receiverId, content } = data;
        const msg = new Message({ sender: senderId, receiver: receiverId, content });
        await msg.save();
        io.to(receiverId).emit('newMessage', msg);
        io.to(senderId).emit('newMessage', msg);
    });

    socket.on('disconnect', () => {
        console.log('User disconnected');
    });
});

// Catch-all for SPA
app.get('/*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
