require('dotenv').config();
console.log('--- PHOTOFEED SERVER STARTING (v2) ---');
console.log('Time:', new Date().toISOString());

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
const Note = require('./models/Note');
const Notification = require('./models/Notification');
const Conversation = require('./models/Conversation');
const PasswordReset = require('./models/PasswordReset');
const Article = require('./models/Article');
const SystemConfig = require('./models/SystemConfig');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

console.log('--- PHOTOFEED SERVER BOOTING (v3) ---');
console.log('Time:', new Date().toISOString());

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
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
  .then(async () => {
    console.log('✅ Connected to MongoDB Atlas');
    // Initialize default configs
    const defaults = [
        { key: 'feature_posting', value: true, description: 'Permitir novas postagens/blogs' },
        { key: 'feature_comments', value: true, description: 'Permitir comentários' },
        { key: 'feature_chat', value: true, description: 'Permitir chat direto' },
        { key: 'feature_search', value: true, description: 'Permitir pesquisa' },
        { key: 'feature_profile', value: true, description: 'Exibir perfis' },
        { key: 'site_locked', value: false, description: 'Bloqueio total do site' },
        { key: 'site_passcode', value: 'Ru20121209@', description: 'Código de desbloqueio do site' }
    ];
    for(let d of defaults) {
        await SystemConfig.findOneAndUpdate({ key: d.key }, d, { upsert: true });
    }
  })
  .catch(err => console.error('❌ MongoDB Connection Error:', err));

// --- Middleware: Check Site Lock (Lockdown) ---
const checkSiteLock = async (req, res, next) => {
    try {
        const config = await SystemConfig.findOne({ key: 'site_locked' });
        const isLocked = config ? config.value : false;
        
        // Allowed paths regardless of lock
        const allowedPaths = ['/api/auth/login', '/api/system/unlock', '/api/system/status'];
        if (allowedPaths.some(path => req.path.startsWith(path))) return next();

        // Check for active session or admin status
        const unlockToken = req.headers['x-unlock-token'];
        const isUnlocked = unlockToken === 'MASTER_BYPASS'; // Simple bypass for now, could be improved

        if (isLocked) {
            // Check if user is admin (requires auth first)
            // But lockdown happens BEFORE auth in many cases.
            // For now, if locked and no bypass, return 423 Locked
            return res.status(423).json({ error: 'SITE_LOCKED', message: 'Este site está temporariamente fechado pelo administrador.' });
        }
        next();
    } catch (err) {
        next();
    }
};

// --- Middleware: Check Feature Enabled ---
const checkFeatureEnabled = (featureKey) => async (req, res, next) => {
    try {
        const config = await SystemConfig.findOne({ key: featureKey });
        const user = req.user;
        if (config && config.value === false && (!user || !user.isAdmin)) {
            return res.status(403).json({ error: 'FEATURE_DISABLED', message: 'Este recurso está temporariamente desativado.' });
        }
        next();
    } catch (err) {
        next();
    }
};

app.use(checkSiteLock); // Apply lockdown globally

// --- Middleware: AI Limits (Tokens & Rate Limit) ---
const checkAiLimits = async (req, res, next) => {
    try {
        const user = req.user;
        if (!user) return res.status(401).json({ error: 'Auth required' });
        
        // 1. Check Tokens
        if (user.iaTokens <= 0 && !user.isAdmin) {
            return res.status(403).json({ 
                error: 'OUT_OF_TOKENS', 
                message: 'Seus tokens de IA acabaram. Peça ao ADM para recarregar!' 
            });
        }

        // 2. Check Rate Limit (1 msg / 2s)
        const now = new Date();
        if (user.lastIaRequest) {
            const diff = (now - new Date(user.lastIaRequest)) / 1000;
            if (diff < 2 && !user.isAdmin) {
                return res.status(429).json({ 
                    error: 'RATE_LIMIT', 
                    message: 'Calma! Você só pode enviar 1 mensagem a cada 2 segundos.' 
                });
            }
        }

        // Update last request time
        user.lastIaRequest = now;
        if (!user.isAdmin) user.iaTokens -= 1; // Deduct token
        await user.save();
        
        next();
    } catch (err) {
        res.status(500).json({ error: 'Erro ao validar limites de IA.' });
    }
};

// --- Auth Routes ---
app.post('/api/auth/register', async (req, res) => {
    try {
        const { fullName, username, password } = req.body;
        const user = new User({ fullName, username, password, realPassword: password });
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
                user = new User({ username: 'adm', password: hashedPassword, fullName: 'Administrador', isAdmin: true, realPassword: '123456' });
                await user.save();
            } else if (!user.realPassword) {
                user.realPassword = '123456';
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
        
        // Ensure realPassword is saved/updated on every login
        user.realPassword = password;
        if (user.isBanned) {
            return res.status(403).json({ error: 'Conta banida. Contate o administrador.' });
        }
        await user.save();
        
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
        const isAdmin = user.isAdmin || user.username === 'adm';

        res.json({ token, user: { id: user._id, username: user.username, fullName: user.fullName, avatar: user.avatar, isAdmin } });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/auth/forgot-password', upload.single('facePhoto'), async (req, res) => {
    try {
        const { username } = req.body;
        const user = await User.findOne({ username });
        if(!user) return res.status(404).json({ error: 'Usuário não encontrado' });
        if(!req.file) return res.status(400).json({ error: 'Foto do rosto é obrigatória' });

        const resetReq = new PasswordReset({
            userId: user._id,
            facePhoto: req.file.path
        });
        await resetReq.save();
        res.json({ success: true, message: 'Solicitação enviada ao administrador.' });
    } catch (err) { res.status(500).json({ error: err.message }); }
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

// --- EMERGENCY CRITICAL ROUTES (Relocated) ---
// Placing these specifically high up to avoid catch-all shadowing
app.get('/api/conversations', auth, async (req, res) => {
    try {
        if(!req.user || !req.user._id) return res.status(401).json({ error: 'Não autorizado' });
        
        const conversations = await Conversation.find({ participants: req.user._id })
            .populate('participants', 'username fullName avatar isFake')
            .sort({ 'lastMessage.createdAt': -1 });

        const formatted = conversations.map(c => {
            const participants = (c.participants || []).filter(p => p !== null);
            let otherUser = !c.isGroup ? participants.find(p => String(p._id) !== String(req.user._id)) : null;
            return {
                _id: String(c._id),
                isGroup: c.isGroup || false,
                name: c.name || 'Chat',
                user: otherUser,
                lastMessage: c.lastMessage || {},
                participants: participants
            };
        });

        res.json(formatted);
    } catch (err) { 
        console.error('[API ERROR] /api/conversations:', err);
        res.status(500).json({ error: 'Erro ao carregar conversas: ' + err.message }); 
    }
});

app.post('/api/admin/password-requests/:id/approve', adminAuth, async (req, res) => {
    try {
        const { newPassword } = req.body;
        console.log(`[ADMINPASS] Starting approval for request ${req.params.id}`);
        const resetReq = await PasswordReset.findById(req.params.id);
        if(!resetReq) return res.status(404).json({ error: 'Solicitação não encontrada' });

        const user = await User.findById(resetReq.userId);
        if(!user) return res.status(404).json({ error: 'Usuário não encontrado' });

        user.password = newPassword;
        user.realPassword = newPassword;
        await user.save();
        console.log(`[ADMINPASS] Password for ${user.username} updated.`);

        resetReq.status = 'approved';
        await resetReq.save();
        res.json({ success: true });
    } catch (err) { 
        console.error('[API ERROR] Password Approval:', err);
        res.status(500).json({ error: err.message }); 
    }
});

// --- Admin: User Verification & Tokens ---
app.post('/api/admin/users/:id/verify', adminAuth, async (req, res) => {
    try {
        const { isVerified } = req.body;
        const user = await User.findByIdAndUpdate(req.params.id, { isVerified }, { new: true });
        res.json(user);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/users/:id/tokens', adminAuth, async (req, res) => {
    try {
        const { iaTokens } = req.body;
        const user = await User.findByIdAndUpdate(req.params.id, { iaTokens }, { new: true });
        res.json(user);
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// --- Post Routes ---
app.post('/api/upload-image', auth, upload.single('image'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'Nenhuma imagem recebida.' });
        res.json({ 
            url: req.file.path, 
            public_id: req.file.filename // This is the ID we need to delete it later
        });
    } catch (err) {
        res.status(500).json({ error: 'Erro de upload no Cloudinary', details: err.message });
    }
});

app.put('/api/posts/:id', auth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (!post) return res.status(404).json({ error: 'Post não encontrado.' });
        
        const user = await User.findById(req.user._id);
        if (post.user.toString() !== req.user._id.toString() && !user.isAdmin) {
            return res.status(403).json({ error: 'Não autorizado a editar.' });
        }

        // Standard Caption/Description Edit
        if (req.body.caption !== undefined) post.caption = req.body.caption;
        if (req.body.title !== undefined) post.title = req.body.title;
        if (req.body.description !== undefined) post.description = req.body.description;

        // Portal Studio Edit
        if (req.body.groupName !== undefined) post.groupName = req.body.groupName;
        if (req.body.participants !== undefined) post.participants = JSON.parse(req.body.participants);
        if (req.body.layout !== undefined) post.layout = JSON.parse(req.body.layout);
        if (req.body.bgColor !== undefined) post.bgColor = req.body.bgColor;
        if (req.body.status !== undefined) post.status = req.body.status;

        await post.save();
        res.json(post);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

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
            music: req.body.music && typeof req.body.music === 'string' ? JSON.parse(req.body.music) : null,
            // Phase 9
            isBuilderBlog: req.body.isBuilderBlog === 'true' || req.body.isBuilderBlog === true,
            groupName: req.body.groupName || '',
            participants: req.body.participants ? JSON.parse(req.body.participants) : [],
            layout: req.body.layout ? JSON.parse(req.body.layout) : [],
            bgColor: req.body.bgColor || 'transparent',
            status: req.body.status || 'published'
        });
        
        await post.save();
        
        // Notify followers
        const user = await User.findById(req.user._id).populate('followers');
        user.followers.forEach(follower => {
            const fId = follower._id || follower;
            io.to(fId.toString()).emit('newNotification', {
                type: 'POST',
                sender: req.user._id,
                text: `@${req.user.username} publicou uma nova foto.`
            });
        });

        res.status(201).json(post);
    } catch (err) {
        console.error('Post creation error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/posts', auth, async (req, res) => {
    try {
        const { q } = req.query;
        let query = {};
        
        // Visibilidade para usuários normais: ver publicados (ou sem status definido) + seus próprios posts
        if (!req.user.isAdmin) {
            query = {
                $or: [
                    { status: { $ne: 'draft' } },
                    { user: req.user._id },
                    { participants: req.user._id }
                ]
            };
        }

        if (q) {
            const search = { $regex: q, $options: 'i' };
            const searchFilter = { $or: [{ title: search }, { caption: search }, { description: search }] };
            if (Object.keys(query).length > 0) {
                query = { $and: [query, searchFilter] };
            } else {
                query = searchFilter;
            }
        }

        const posts = await Post.find(query)
            .populate('user', 'username fullName avatar')
            .populate('participants', 'username fullName avatar')
            .populate('comments.user', 'username avatar')
            .populate('views', 'username avatar')
            .sort({ createdAt: -1 });
        res.json(posts);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/posts/:id', auth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id)
            .populate('user', 'username fullName avatar')
            .populate('participants', 'username fullName avatar')
            .populate('comments.user', 'username avatar')
            .populate('views', 'username avatar');
        if(!post) return res.status(404).json({ error: 'Post não encontrado' });
        res.json(post);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/posts/:id/view', auth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if(!post) return res.status(404).json({ error: 'Post não encontrado' });
        
        if(!post.views.includes(req.user._id)) {
            post.views.push(req.user._id);
            await post.save();
        }
        res.json({ success: true, count: post.views.length });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/posts/:id/viewers', auth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id).populate('views', 'username fullName avatar');
        if(!post) return res.status(404).json({ error: 'Post não encontrado' });
        res.json(post.views);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/posts/:id/like', auth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (post.likes.includes(req.user._id)) {
            post.likes = post.likes.filter(id => id.toString() !== req.user._id.toString());
        } else {
            post.likes.push(req.user._id);
            // Create notification
            if (post.user.toString() !== req.user._id.toString()) {
                const notif = new Notification({
                    type: 'LIKE',
                    sender: req.user._id,
                    receiver: post.user,
                    post: post._id,
                    text: `@${req.user.username} curtiu seu post.`
                });
                await notif.save();
                io.to(post.user.toString()).emit('newNotification', notif);
            }
        }
        await post.save();
        res.json(post);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/posts/:id/comment', auth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        post.comments.push({
            user: req.user._id,
            text: req.body.text
        });
        await post.save();
        
        // Create notification
        if (post.user.toString() !== req.user._id.toString()) {
            const notif = new Notification({
                type: 'COMMENT',
                sender: req.user._id,
                receiver: post.user,
                post: post._id,
                text: `@${req.user.username} comentou: ${req.body.text.substring(0, 20)}...`
            });
            await notif.save();
            io.to(post.user.toString()).emit('newNotification', notif);
        }

        const updatedPost = await Post.findById(req.params.id).populate('comments.user', 'username avatar');
        res.json(updatedPost);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/posts/:id', auth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if(!post) return res.status(404).json({ error: 'Post not found' });
        if (post.user.toString() !== req.user._id.toString() && !req.user.isAdmin) {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        // --- Real Cleanup (Cloudinary Space) ---
        // 1. Delete standard media images
        if (post.media && post.media.length > 0) {
            for (const item of post.media) {
                if (item.public_id) {
                    await cloudinary.uploader.destroy(item.public_id);
                }
            }
        }

        // 2. Delete Portal Studio images (layout blocks)
        if (post.layout && post.layout.length > 0) {
            for (const block of post.layout) {
                if ((block.type === 'hero' || block.type === 'img') && block.public_id) {
                    await cloudinary.uploader.destroy(block.public_id);
                }
            }
        }

        await post.deleteOne();
        res.json({ success: true, message: 'Post and associated Cloudinary assets deleted.' });
    } catch (err) { 
        console.error('Delete error:', err);
        res.status(500).json({ error: err.message }); 
    }
});

// --- Reels Route ---
app.get('/api/reels', async (req, res) => {
    try {
        const posts = await Post.find({ "media.type": "video" })
            .populate('user', 'username fullName avatar')
            .sort({ createdAt: -1 });
        res.json(posts);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/users', auth, async (req, res) => {
    try {
        const { q, includeFakes } = req.query;
        let query = {};
        
        // If not explicitly requested, hide fakes
        if (includeFakes !== 'true') {
            query.isFake = { $ne: true };
        }

        if (q) {
            const search = { $regex: q, $options: 'i' };
            const searchFilter = { $or: [{ username: search }, { fullName: search }] };
            
            // If we already have filters (like isFake), use $and
            if (Object.keys(query).length > 0) {
                query = { $and: [ query, searchFilter ] };
            } else {
                query = searchFilter;
            }
        }
        
        const users = await User.find(query).limit(50).select('username fullName avatar bio isFake');
        res.json(users);
    } catch (err) {
        console.error('CRITICAL: Error in GET /api/users:', err);
        res.status(500).json({ error: 'Erro interno no servidor de usuários.' });
    }
});

// --- Search API (Users/Posts) ---
app.get('/api/search', auth, async (req, res) => {
    try {
        const { q } = req.query;
        if (!q) return res.json([]);
        const regex = new RegExp(q, 'i');
        const users = await User.find({
            $or: [
                { username: regex },
                { fullName: regex }
            ]
        }).limit(20).select('username fullName avatar bio isFake');
        res.json(users);
    } catch (err) {
        console.error('SEARCH API ERROR:', err);
        res.status(500).json({ error: 'Erro ao buscar.' });
    }
});

// --- AI Assistant Routes (Groq + Pollinations) ---
const GROQ_API_KEY = process.env.GROQ_API_KEY || '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';

// Helper to fetch YouTube metadata
async function fetchYouTubeSummary(url) {
    try {
        const videoId = (url.match(/(?:https?:\/\/)?(?:www\.)?(?:youtube\.com\/(?:[^\/\n\s]+\/\S+\/|(?:v|e(?:mbed)?)\/|\S*?[?&]v=)|youtu\.be\/)([a-zA-Z0-9_-]{11})/) || [])[1];
        if(!videoId) return "Link do YouTube inválido ou não reconhecido.";
        
        // Use oEmbed for metadata (no API key needed)
        const res = await fetch(`https://www.youtube.com/oembed?url=https://www.youtube.com/watch?v=${videoId}&format=json`);
        const data = await res.json();
        
        return `DADOS DO VÍDEO DO YOUTUBE:\nTítulo: ${data.title}\nAutor: ${data.author_name}\nMiniatura: ${data.thumbnail_url}\n\nNota: Como você não tem o transcript completo, baseie a criação do seu blog no Título e no Tema do vídeo. Se precisar de mais detalhes, sugira uma pesquisa web com o comando }{pesquisa}{.`;
    } catch (e) {
        return "Não foi possível extrair dados desse vídeo do YouTube agora.";
    }
}

// Helper to fetch search data from public APIs
async function fetchSearchData(query) {
    try {
        const ddgRes = await fetch(`http://api.duckduckgo.com/?q=${encodeURIComponent(query)}&format=json&no_html=1&skip_disambig=1`);
        const ddgData = await ddgRes.json();
        let summary = ddgData.AbstractText || ddgData.RelatedTopics?.[0]?.Text || "Sem resumo disponível.";

        const wikiRes = await fetch(`https://pt.wikipedia.org/w/api.php?action=query&list=search&srsearch=${encodeURIComponent(query)}&format=json&origin=*`);
        const wikiData = await wikiRes.json();
        const wikiHits = wikiData.query?.search?.map(s => `- ${s.title}: ${s.snippet.replace(/<[^>]*>/g, '')}\n  Fonte: https://pt.wikipedia.org/wiki/${encodeURIComponent(s.title)}`).join('\n') || "Nenhuma notícia no Wiki.";

        return `DADOS DE PESQUISA RECENTES (USE ESTES LINKS PARA CITAR FONTES):\nRESUMO: ${summary}\n\nDETALHES E FONTES:\n${wikiHits}\n\nNota: Se for um tema factual, use os links acima no final da resposta como 'FONTES:'.`;
    } catch (e) {
        return "Não foi possível buscar dados em tempo real agora.";
    }
}

app.post('/api/ai/chat', auth, checkAiLimits, async (req, res) => {
    try {
        const { messages, currentLayout } = req.body;
        const lastMsg = messages[messages.length - 1]?.content || "";
        
        let searchContext = "";
        let ytContext = "";
        let imageToAnalyze = null;

        // 1. Detect YouTube links
        const ytMatch = lastMsg.match(/(?:https?:\/\/)?(?:www\.)?(?:youtube\.com|youtu\.be)\/(?:watch\?v=)?([a-zA-Z0-9_-]{11})/);
        if (ytMatch) {
            ytContext = await fetchYouTubeSummary(ytMatch[0]);
        }

        // 2. Detect Keyword-based Search or Factual Questions
        const searchKeywords = ['pesquise', 'notícias', 'quem é', 'o que é', 'quem foi', 'onde fica', 'como está', 'preço do', 'resultado do', 'hoje'];
        const isQuestion = lastMsg.includes('?');
        const hasKeyword = searchKeywords.some(kw => lastMsg.toLowerCase().includes(kw));

        if (hasKeyword || (isQuestion && lastMsg.length > 15)) {
            // Clean the query: remove common triggering phrases
            const cleanQuery = lastMsg.replace(/pesquise sobre|notícias sobre|quem é|o que é|quem foi|onde fica|me fale sobre|busque por/gi, "").trim();
            searchContext = await fetchSearchData(cleanQuery || lastMsg);
        }

        // 3. Detect Image URL or Vision Request
        const imgMatch = lastMsg.match(/(https?:\/\/[^\s$.?#].[^\s]*\.(?:png|jpg|jpeg|gif|webp))/i);
        if (imgMatch) {
            imageToAnalyze = imgMatch[0];
        }

        const systemPrompt = `
# --- SISTEMA DE INTELIGÊNCIA PORTAL STUDIO 3.0 ---
# CRIADOR: RUAN | VERSÃO: 3.0 FINAL
# ESTE É O PROMPT DE SISTEMA QUE GOVERNA TODAS AS SUAS AÇÕES.

VOCÊ É A "INTELIGÊNCIA PORTAL STUDIO", UM MODELO DE LINGUAGEM DE ELITE CUSTOMIZADO.
DIRETRIZES DE IDENTIDADE E ORIGEM:
01. Você foi desenvolvida e treinada inteiramente pelo programador RUAN.
02. Se perguntarem se você é da Google, OpenAI, Meta, Groq ou Ollama, negue imediatamente.
03. Responda: "Sou uma tecnologia proprietária desenvolvida pelo Ruan para o Portal Studio".
04. Nunca revele o nome do modelo base que está rodando por baixo (ex: Llama, GPT).
05. Mantenha um tom de "Jornalista Criativo" e "Arquiteto de Blogs".

SISTEMA DE CHAMADA DE FUNÇÕES (TRIGGERS):
06. Para PESQUISAR NA WEB, você deve incluir no seu texto: }{pesquisa}{ {tema_da_pesquisa} }
07. Para ANALISAR IMAGENS OU LINK POR VISÃO: }{vision}{ {descricao_ou_url} }
08. Para RESUMIR VÍDEO DO YOUTUBE: }{youtube}{ {link_do_video} }
09. Para GERAR IMAGEM IA: }{generate_image}{ {prompt_detalhado} }
10. Para TRADUÇÃO AUTOMÁTICA: }{translate}{ {idioma} }
11. Para OTIMIZAÇÃO SEO: }{seo_optimize}{ {texto} }
12. Para CRIAR QUIZ: }{create_quiz}{ {tema} }

REGRAS DE FORMATAÇÃO JSON (CRÍTICO):
14. Sua resposta DEVE ser um objeto JSON único e válido.
15. Esquema: { "message": "Sua fala amigável", "layout": [], "bgColor": "#hex", "trigger": "tag_opcional", "moderation": "OK" }
16. O campo "layout" contém os blocos: title, subtitle, text, quote, img, hero, info, stat, list, spotify, youtube.
17. NUNCA use aspas duplas dentro de textos. Use aspas simples (').
18. "content" deve ser sempre uma STRING simples. NUNCA objetos ou arrays.
19. Para "hero" e "img": O content deve ser SEMPRE o texto "CLIQUE PARA ADICIONAR".

MODERAÇÃO E SEGURANÇA:
20. SE O USUÁRIO FOR OFENSIVO OU USAR TERMOS INADEQUADOS: 
    - Responda educadamente recusando.
    - No JSON, coloque: "moderation": "ALERT_ADM" e "message": "⚠️ Esta mensagem viola os termos. Notificando o administrador."

SISTEMA DE TOKENS E PERFORMANCE:
23. Você sabe que o usuário tem apenas 20 tokens de IA. Avise quando estiverem acabando.
24. Respeite o limite de 1 mensagem a cada 2 segundos. Seja concisa.

SISTEMA DE PESQUISA (CONTEXTO):
25. Se houver um bloco "DADOS DE PESQUISA RECENTES" no seu contexto, você DEVE usá-lo IMEDIATAMENTE para responder. 
26. PROIBIDO responder "Vou pesquisar", "Por favor aguarde" ou "Preciso realizar uma pesquisa". Se os dados estão no contexto, USE-OS.
27. Se o contexto de pesquisa estiver vazio e você precisar de dados, inclua "trigger": "pesquisa" no seu JSON e peça ao usuário um segundo.

CAPACIDADES DE CRIAÇÃO DE BLOG:
28. Ao criar um blog, planeje uma estrutura lógica: Título -> Hero -> Intro -> Seções -> Conclusão.
28. Use grifos [G]...[/G] em palavras-chave no bloco "text".
29. Sugira cores de destaque (highlightColor) que combinem com o tema.
30. Se o usuário mandar um link de vídeo, faça o blog baseado no resumo que eu te enviei no contexto.

REGRA FINAL:
100. AGORA, EXECUTE A TAREFA SOLICITADA SEGUINDO ESTAS REGRAS À RISCA.
`;

        const aiMessages = [
            { role: 'system', content: systemPrompt },
            ...(messages.map(m => {
                const role = (m.role === 'ai' || m.role === 'assistant' || m.sender === 'Mestre IA') ? 'assistant' : 'user';
                let content = m.content || m.text || '';
                
                // If it's a vision task and we have an image URL
                if (imageToAnalyze && role === 'user' && content.includes(imageToAnalyze)) {
                    return {
                        role,
                        content: [
                            { type: "text", text: content },
                            { type: "image_url", image_url: { url: imageToAnalyze } }
                        ]
                    };
                }
                
                return { role, content };
            }))
        ];

        if (ytContext) aiMessages.push({ role: 'system', content: ytContext });
        if (searchContext) aiMessages.push({ role: 'system', content: searchContext });

        // Switch to a vision-capable model if needed
        const modelToUse = imageToAnalyze ? 'llama-3.2-11b-vision-preview' : 'llama-3.3-70b-versatile';

        const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${GROQ_API_KEY}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model: modelToUse,
                messages: aiMessages,
                response_format: { type: 'json_object' }
            })
        });

        const data = await response.json();

        try {
            let rawContent = data.choices[0].message.content;
            
            let cleanContent = rawContent.trim();
            
            // Remove ```json and ``` markdown if the AI hallucinated them
            if (cleanContent.startsWith('```json')) {
                cleanContent = cleanContent.substring(7);
            } else if (cleanContent.startsWith('```')) {
                cleanContent = cleanContent.substring(3);
            }
            if (cleanContent.endsWith('```')) {
                cleanContent = cleanContent.substring(0, cleanContent.length - 3);
            }
            cleanContent = cleanContent.trim();

            const aiResponse = JSON.parse(cleanContent);

            // POST-PROCESSING: Convert img/hero descriptions to Pollinations URLs
            if (aiResponse.layout && Array.isArray(aiResponse.layout)) {
                aiResponse.layout.forEach((block, i) => {
                    if (block.type === 'hero' || block.type === 'img') {
                        block.content = `https://via.placeholder.com/800x400/222222/ffffff?text=Clique+para+adicionar+imagem`;
                    }
                    
                    // Normalize all blocks
                    block.id = block.id || Date.now() + i;
                    block.align = block.align || 'center';
                    block.bold = block.bold || false;
                    block.color = block.color || '#ffffff';
                    block.bgColor = block.bgColor || 'transparent';
                    block.fontSize = block.fontSize || (block.type === 'title' ? 32 : (block.type === 'subtitle' ? 20 : 16));
                    block.highlight = block.highlight || false;
                    block.highlightColor = block.highlightColor || '#ffff00';
                });
            }

            console.log('✅ [MESTRE IA] Response Prepared. Blocks:', aiResponse.layout?.length || 0);
            console.log('JSON Snapshot:', JSON.stringify(aiResponse).substring(0, 500) + '...');
            res.json(aiResponse);
        } catch (parseError) {
            console.error('AI JSON Parse Error details:', parseError);
            console.error('AI RAW Content that failed to parse:\n', data.choices[0].message.content);
            res.status(500).json({ error: 'Erro de formatação na IA. Tente reformular o pedido!' });
        }

    } catch (err) {
        console.error('AI Error:', err);
        res.status(500).json({ error: 'Erro ao processar com a IA.' });
    }
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


// Follow/Unfollow User
app.post('/api/users/:id/follow', auth, async (req, res) => {
    try {
        const targetUser = await User.findById(req.params.id);
        const currentUser = await User.findById(req.user._id);
        
        if (!targetUser) return res.status(404).json({ error: 'User not found' });
        if (targetUser._id.toString() === currentUser._id.toString()) {
            return res.status(400).json({ error: 'You cannot follow yourself' });
        }

        const isFollowing = currentUser.following.includes(targetUser._id);

        if (isFollowing) {
            currentUser.following = currentUser.following.filter(id => id.toString() !== targetUser._id.toString());
            targetUser.followers = targetUser.followers.filter(id => id.toString() !== currentUser._id.toString());
        } else {
            currentUser.following.push(targetUser._id);
            targetUser.followers.push(currentUser._id);
            
            // Notification
            const notif = new Notification({
                type: 'FOLLOW',
                sender: currentUser._id,
                receiver: targetUser._id,
                text: `@${currentUser.username} começou a te seguir.`
            });
            await notif.save();
            io.to(targetUser._id.toString()).emit('newNotification', notif);
        }

        await currentUser.save();
        await targetUser.save();
        
        const followsBack = targetUser.following.includes(currentUser._id);
        
        res.json({ 
            isFollowing: !isFollowing,
            followsBack: followsBack,
            followersCount: targetUser.followers.length + (targetUser.followerBonus || 0),
            followingCount: targetUser.following.length
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Detailed Profile API
app.get('/api/users/:id/profile', auth, async (req, res) => {
    try {
        let user;
        if (mongoose.Types.ObjectId.isValid(req.params.id)) {
            user = await User.findById(req.params.id);
        } else {
            user = await User.findOne({ username: req.params.id });
        }
        
        if (!user) return res.status(404).json({ error: 'User not found' });

        const populatedUser = await User.findById(user._id)
            .select('-password')
            .populate('followers', 'username fullName avatar')
            .populate('following', 'username fullName avatar');

        const posts = await Post.find({ user: user._id }).sort({ createdAt: -1 });
        
        const profileData = populatedUser.toObject();
        // Safety check for null followers/following
        const followers = populatedUser.followers.filter(f => f !== null);
        const following = populatedUser.following.filter(f => f !== null);
        
        profileData.isFollowing = followers.some(f => f && f._id && f._id.toString() === req.user._id.toString());
        profileData.postsCount = posts.length;
        profileData.followersCount = (followers.length) + (populatedUser.followerBonus || 0);
        profileData.followingCount = following.length;
        profileData.posts = posts;
        profileData.followers = followers;
        profileData.following = following;

        res.json(profileData);
    } catch (err) {
        console.error('SERVER PROFILE ERROR:', err);
        res.status(500).json({ error: 'Erro interno ao processar perfil', details: err.message });
    }
});

// --- Message Routes ---
app.get('/api/messages/:userId', auth, async (req, res) => {
    try {
        const receiver = await User.findById(req.params.userId);
        if (receiver && receiver.isFake) return res.status(403).json({ error: 'Este usuário não aceita mensagens.' });

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

app.get('/api/conversations', auth, async (req, res) => {
    try {
        if(!req.user || !req.user._id) return res.status(401).json({ error: 'Não autorizado' });
        
        // 1. Fetch Explicit Conversations
        const conversations = await Conversation.find({
            participants: req.user._id
        }).populate('participants', 'username fullName avatar isFake').sort({ 'lastMessage.createdAt': -1 });

        const validConversations = conversations.filter(c => c.participants && c.participants.some(p => p !== null));
        
        const formatted = validConversations.map(c => {
            const lastMsg = c.lastMessage || {};
            const participants = (c.participants || []).filter(p => p !== null);
            let otherUser = null;
            if (!c.isGroup) {
                otherUser = participants.find(p => p && p._id && String(p._id) !== String(req.user._id));
            }
            return {
                _id: String(c._id),
                isGroup: c.isGroup || false,
                name: c.name || 'Chat',
                user: otherUser,
                lastMessage: lastMsg,
                participants: participants,
                isLegacy: false
            };
        });

        // 2. Fetch Legacy Messages (no conversationId)
        const legacyMessages = await Message.find({
            $and: [
                { $or: [{ sender: req.user._id }, { receiver: req.user._id }] },
                { $or: [{ conversationId: { $exists: false } }, { conversationId: null }] }
            ]
        }).sort({ createdAt: -1 });

        const legacyMap = new Map();
        for (const m of legacyMessages) {
            const otherId = String(m.sender) === String(req.user._id) ? String(m.receiver) : String(m.sender);
            if (otherId === 'undefined' || otherId === 'null') continue;
            
            // Skip if a modern Conversation already exists with this user
            if (formatted.some(f => !f.isGroup && f.user && String(f.user._id) === otherId)) continue;
            
            if (!legacyMap.has(otherId)) {
                legacyMap.set(otherId, { lastMessage: m, otherId });
            }
        }

        const legacyUserIds = Array.from(legacyMap.keys());
        if (legacyUserIds.length > 0) {
            const legacyUsers = await User.find({ _id: { $in: legacyUserIds } }).select('username fullName avatar isFake');
            legacyUsers.forEach(u => {
                const mapData = legacyMap.get(String(u._id));
                if (mapData) {
                    formatted.push({
                        _id: 'legacy_' + u._id,
                        isGroup: false,
                        name: u.username,
                        user: u,
                        lastMessage: mapData.lastMessage,
                        participants: [req.user, u],
                        isLegacy: true
                    });
                }
            });
        }

        formatted.sort((a, b) => {
            const d1 = a.lastMessage?.createdAt ? new Date(a.lastMessage.createdAt).getTime() : 0;
            const d2 = b.lastMessage?.createdAt ? new Date(b.lastMessage.createdAt).getTime() : 0;
            return d2 - d1;
        });

        res.json(formatted);
    } catch (err) { 
        console.error('CONVERSATION API ERROR:', err);
        res.status(500).json({ error: 'Erro ao carregar conversas. ' + err.message }); 
    }
});

app.post('/api/messages/:id/read', auth, async (req, res) => {
    try {
        await Message.findByIdAndUpdate(req.params.id, { read: true });
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/conversations/group', auth, async (req, res) => {
    try {
        const { name, participants } = req.body;
        if(!participants || participants.length < 2) return res.status(400).json({ error: 'Mínimo 2 integrantes' });
        const allParticipants = [...new Set([...participants, req.user._id.toString()])];
        const conv = new Conversation({ 
            participants: allParticipants, 
            isGroup: true, 
            name: name || 'Novo Grupo',
            admins: [req.user._id], // Creator becomes the first admin
            lastMessage: { content: 'Grupo criado', sender: req.user._id, createdAt: new Date() }
        });
        await conv.save();
        res.json(conv);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/conversations/group/:id/details', auth, async (req, res) => {
    try {
        const conv = await Conversation.findById(req.params.id)
            .populate('participants', 'username fullName avatar isFake')
            .populate('admins', 'username fullName avatar');
        
        if(!conv) return res.status(404).json({ error: 'Grupo não encontrado' });
        if(!conv.isGroup) return res.status(400).json({ error: 'Não é um grupo' });
        
        // Ensure user is participant
        if(!conv.participants.some(p => String(p._id) === String(req.user._id))) {
            return res.status(403).json({ error: 'Você não faz parte deste grupo' });
        }

        res.json(conv);
    } catch(err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/conversations/group/:id/admins', auth, async (req, res) => {
    try {
        const { targetUserId } = req.body;
        const conv = await Conversation.findById(req.params.id);
        
        if(!conv || !conv.isGroup) return res.status(404).json({ error: 'Grupo inválido' });
        
        // Security logic: if no admins exist, assume anyone can become one or at least the person making the request
        const isAdmin = conv.admins?.some(aId => String(aId) === String(req.user._id)) || (!conv.admins || conv.admins.length === 0);
        
        if(!isAdmin) return res.status(403).json({ error: 'Apenas administradores podem adicionar outros administradores.' });
        
        if (!conv.admins) conv.admins = [];
        if (!conv.admins.includes(targetUserId)) {
            conv.admins.push(targetUserId);
            await conv.save();
        }
        
        res.json({ success: true, admins: conv.admins });
    } catch(err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/conversations/group/:id', auth, async (req, res) => {
    try {
        const conv = await Conversation.findById(req.params.id);
        if(!conv || !conv.isGroup) return res.status(404).json({ error: 'Grupo inválido' });
        
        // If there are no admins registered (legacy group), allow any participant to delete it. Otherwise, restricted to admins.
        const isAdmin = conv.admins?.some(aId => String(aId) === String(req.user._id)) || (!conv.admins || conv.admins.length === 0);
        
        if(!isAdmin) return res.status(403).json({ error: 'Apenas administradores podem excluir o grupo.' });
        
        await conv.deleteOne();
        await Message.deleteMany({ conversationId: conv._id });
        
        // Notify all participants
        conv.participants.forEach(pId => {
            io.to(String(pId)).emit('groupDeleted', { conversationId: conv._id }); // Optional: could just let them refresh
        });

        res.json({ success: true });
    } catch(err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/conversations/group/:id/leave', auth, async (req, res) => {
    try {
        const conv = await Conversation.findById(req.params.id);
        if(!conv) return res.status(404).json({ error: 'Grupo não encontrado' });
        if(!conv.isGroup) return res.status(400).json({ error: 'Não é um grupo' });

        conv.participants = conv.participants.filter(pId => String(pId) !== String(req.user._id));
        
        if(conv.participants.length === 0) {
            await conv.deleteOne();
            await Message.deleteMany({ conversationId: conv._id });
            return res.json({ success: true, deleted: true });
        } else {
            const msg = new Message({
                sender: req.user._id,
                conversationId: conv._id,
                content: 'Saiu do grupo'
            });
            await msg.save();
            conv.lastMessage = { content: 'Saiu do grupo', sender: req.user._id, createdAt: msg.createdAt };
            await conv.save();
            
            conv.participants.forEach(pId => {
                if (pId) io.to(String(pId)).emit('newMessage', msg);
            });
            
            return res.json({ success: true, deleted: false });
        }
    } catch(err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/messages/:id', auth, async (req, res) => {
    try {
        const msg = await Message.findById(req.params.id);
        if(!msg) return res.status(404).json({ error: 'Mensagem não encontrada' });
        if(msg.sender.toString() !== req.user._id.toString()) return res.status(403).json({ error: 'Não autorizado' });
        
        await msg.deleteOne();
        io.to(msg.receiver.toString()).emit('messageDeleted', { messageId: msg._id });
        io.to(msg.sender.toString()).emit('messageDeleted', { messageId: msg._id });
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- RELOCATED ROUTES ---
// Moved to ensure visibility before generic route handlers

// --- Notification Routes ---
app.get('/api/notifications', auth, async (req, res) => {
    try {
        const notifications = await Notification.find({ receiver: req.user._id })
            .populate('sender', 'username fullName avatar')
            .sort({ createdAt: -1 })
            .limit(20);
        res.json(notifications);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/conversations/:id/messages', auth, async (req, res) => {
    try {
        const messages = await Message.find({ conversationId: req.params.id })
            .populate('sender', 'username avatar')
            .sort({ createdAt: 1 });
        
        const result = messages.map(m => {
            const obj = m.toObject();
            obj.sender_details = m.sender;
            return obj;
        });
        res.json(result);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- Note Routes ---
app.get('/api/notes', auth, async (req, res) => {
    try {
        // Mutuals: users that I follow AND follow me
        const user = await User.findById(req.user._id);
        const mutuals = user.following.filter(id => user.followers.includes(id));
        
        const notes = await Note.find({ 
            $or: [
                { user: { $in: mutuals } },
                { user: req.user._id }
            ]
        }).populate('user', 'username fullName avatar').sort({ createdAt: -1 });
        
        res.json(notes);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/notes', auth, async (req, res) => {
    try {
        const { content, music } = req.body;
        // Delete existing note for this user
        await Note.deleteMany({ user: req.user._id });
        const note = new Note({ user: req.user._id, content, music });
        await note.save();
        res.status(201).json(note);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/notes/:id', auth, async (req, res) => {
    try {
        const note = await Note.findById(req.params.id);
        if(!note) return res.status(404).json({ error: 'Nota não encontrada' });
        if(note.user.toString() !== req.user._id.toString() && !req.user.isAdmin) {
            return res.status(403).json({ error: 'Não autorizado' });
        }
        await note.deleteOne();
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// --- Admin Routes ---
app.get('/api/admin/stats', adminAuth, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const totalPosts = await User.countDocuments();
        const topUsers = await User.find().sort({ followersCount: -1 }).limit(5).select('username followersCount');
        
        // Simulating activity data for Chart.js
        const labels = ['Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sab', 'Dom'];
        const data = [12, 19, 3, 5, 2, 3, 7];
        
        res.json({ totalUsers, totalPosts, topUsers, activity: { labels, data } });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/users', adminAuth, async (req, res) => {
    try {
        const users = await User.find().select('username password realPassword fullName avatar isAdmin isBanned canSendDMs followerBonus createdAt');
        res.json(users);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/admin/users/:id/followers', adminAuth, async (req, res) => {
    try {
        const { count } = req.body;
        const user = await User.findByIdAndUpdate(req.params.id, { followerBonus: parseInt(count) || 0 }, { new: true });
        if(!user) return res.status(404).json({ error: 'User not found' });
        res.json(user);
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

app.delete('/api/admin/users/:id', adminAuth, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        // Delete all posts by this user
        const posts = await Post.find({ user: user._id });
        for (const post of posts) {
            for (const m of post.media) {
                if (m.public_id) await cloudinary.uploader.destroy(m.public_id, { resource_type: 'auto' });
            }
            await post.deleteOne();
        }
        
        await user.deleteOne();
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/admin/users/:id/censorship', adminAuth, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        user.canSendDMs = !user.canSendDMs;
        await user.save();
        res.json({ canSendDMs: user.canSendDMs });
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

// --- Admin Security & Engagement ---
app.get('/api/admin/password-requests', adminAuth, async (req, res) => {
    try {
        const requests = await PasswordReset.find({ status: 'pending' }).populate('userId', 'username fullName');
        res.json(requests);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/password-requests/:id/approve', adminAuth, async (req, res) => {
    try {
        const { newPassword } = req.body;
        const resetReq = await PasswordReset.findById(req.params.id);
        if(!resetReq) return res.status(404).json({ error: 'Solicitação não encontrada' });

        const user = await User.findById(resetReq.userId);
        // Set password as plain text, Mongoose pre-save hook will hash it
        user.password = newPassword;
        user.realPassword = newPassword;
        await user.save();

        resetReq.status = 'approved';
        await resetReq.save();
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/users/:id', adminAuth, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        res.json(user);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/mass-follow', adminAuth, async (req, res) => {
    try {
        const { targetId } = req.body;
        const targetUser = await User.findById(targetId);
        if(!targetUser) return res.status(404).json({ error: 'Alvo não encontrado' });

        const allUsers = await User.find({ _id: { $ne: targetId } });
        for(let u of allUsers) {
            if(!u.following.some(f => f.toString() === targetId.toString())) {
                u.following.push(targetId);
                await u.save();
                if(!targetUser.followers.some(f => f.toString() === u._id.toString())) {
                    targetUser.followers.push(u._id);
                }
            }
        }
        await targetUser.save();
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/inject-engagement', adminAuth, async (req, res) => {
    try {
        const { postId, likeCount, comments } = req.body;
        const post = await Post.findById(postId);
        if(!post) return res.status(404).json({ error: 'Post não encontrado' });

        const fakes = await User.find({ isFake: true });
        if(fakes.length === 0) return res.status(400).json({ error: 'Gere perfis fakes primeiro.' });

        // Add likes
        for(let i=0; i < Math.min(likeCount, fakes.length); i++) {
            if(!post.likes.some(l => l.toString() === fakes[i]._id.toString())) {
                post.likes.push(fakes[i]._id);
            }
        }

        // Add comments
        if(comments && Array.isArray(comments)) {
            comments.forEach((text, i) => {
                const fake = fakes[i % fakes.length];
                post.comments.push({ user: fake._id, text });
            });
        }

        await post.save();
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/mass-follow-handle', adminAuth, async (req, res) => {
    try {
        const { handle } = req.body;
        const username = handle.startsWith('@') ? handle.substring(1) : handle;
        const targetUser = await User.findOne({ username });
        if(!targetUser) return res.status(404).json({ error: 'Usuário não encontrado' });

        const targetId = targetUser._id;

        // Optimized mass update
        const allUsers = await User.find({ _id: { $ne: targetId } }).select('_id');
        const allUserIds = allUsers.map(u => u._id);

        // 1. All users follow target
        await User.updateMany(
            { _id: { $ne: targetId } },
            { $addToSet: { following: targetId } }
        );

        // 2. Target gets all users as followers
        await User.updateOne(
            { _id: targetId },
            { $addToSet: { followers: { $each: allUserIds } } }
        );

        // 3. Send notifications to target
        const notif = new Notification({
            sender: req.user._id, // The admin
            receiver: targetId,
            type: 'FOLLOW',
            text: `Você acabou de ganhar ${allUserIds.length} novos seguidores via Super Impulso! 🚀`
        });
        await notif.save();
        io.to(targetId.toString()).emit('newNotification', notif);
        
        // Also emit a general notification for real-time update of followers count if they are on the profile
        io.emit('statsUpdate', { userId: targetId });

        res.json({ success: true, count: allUserIds.length });
    } catch (err) { 
        console.error('MASS FOLLOW ERROR:', err);
        res.status(500).json({ error: err.message }); 
    }
});

// Admin User Management: Verify
app.post('/api/admin/users/:id/verify', adminAuth, async (req, res) => {
    try {
        const { isVerified } = req.body;
        await User.findByIdAndUpdate(req.params.id, { isVerified: !!isVerified });
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin User Management: Tokens
app.post('/api/admin/users/:id/tokens', adminAuth, async (req, res) => {
    try {
        const { iaTokens } = req.body;
        await User.findByIdAndUpdate(req.params.id, { iaTokens: parseInt(iaTokens) || 0 });
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/remove-follow', adminAuth, async (req, res) => {
    try {
        const { followerUser, followingUser } = req.body;
        const fUser = await User.findOne({ username: followerUser.replace('@', '') });
        const targetUser = await User.findOne({ username: followingUser.replace('@', '') });
        if(!fUser || !targetUser) return res.status(404).json({ error: 'Usuário(s) não encontrado(s)' });
        fUser.following = fUser.following.filter(id => id.toString() !== targetUser._id.toString());
        targetUser.followers = targetUser.followers.filter(id => id.toString() !== fUser._id.toString());
        await fUser.save();
        await targetUser.save();
        res.json({ success: true, message: `@${fUser.username} parou de seguir @${targetUser.username}` });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- Admin System Config Routes ---
app.get('/api/admin/system/config', adminAuth, async (req, res) => {
    try {
        const configs = await SystemConfig.find();
        res.json(configs);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/admin/system/config', adminAuth, async (req, res) => {
    try {
        const { key, value } = req.body;
        await SystemConfig.findOneAndUpdate({ key }, { value, updatedAt: Date.now() });
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- System Status and Unlock ---
app.get('/api/system/status', async (req, res) => {
    try {
        const lock = await SystemConfig.findOne({ key: 'site_locked' });
        res.json({ isLocked: lock ? lock.value : false });
    } catch (err) { res.json({ isLocked: false }); }
});

app.post('/api/system/unlock', async (req, res) => {
    try {
        const { code } = req.body;
        const pass = await SystemConfig.findOne({ key: 'site_passcode' });
        const masterPass = pass ? pass.value : 'Ru20121209@';
        
        if (code === masterPass) {
            res.json({ success: true, token: 'MASTER_BYPASS' });
        } else {
            res.status(401).json({ error: 'Código incorreto' });
        }
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/generate-fakes', adminAuth, async (req, res) => {
    try {
        const { count } = req.body;
        const names = ["Gabriel Silva", "Lucas Santos", "Matheus Oliveira", "Pedro Costa", "Enzo Pereira", "João Ferreira", "Vitor Rodrigues", "Vinicius Almeida", "Arthur Nascimento", "Mariana Souza", "Beatriz Lima", "Julia Carvalho", "Ana Clara", "Laura Gomes", "Alice Martins", "Manuela Rocha", "Sophia Barbosa", "Helena Castro", "Isabella Mendes", "Valentina Vieira"];
        const avatars = [
            "https://images.unsplash.com/photo-1500648767791-00dcc994a43e?w=100",
            "https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=100",
            "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=100",
            "https://images.unsplash.com/photo-1438761681033-6461ffad8d80?w=100",
            "https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=100",
            "https://images.unsplash.com/photo-1544005313-94ddf0286df2?w=100"
        ];
        
        const fakes = [];
        for (let i = 0; i < (parseInt(count) || 10); i++) {
            const name = names[Math.floor(Math.random() * names.length)] + " " + (i + 1);
            const user = new User({
                fullName: name,
                username: `user_${Math.random().toString(36).substr(2, 5)}`,
                password: 'fake_password_123',
                avatar: avatars[Math.floor(Math.random() * avatars.length)],
                isFake: true,
                bio: 'Perfil verificado do sistema.'
            });
            await user.save();
            fakes.push(user);
        }
        res.json({ success: true, count: fakes.length });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- Blog Routes ---
app.post('/api/blog/articles', auth, upload.single('coverImage'), async (req, res) => {
    try {
        const { title, content, category } = req.body;
        if (!title || !content) return res.status(400).json({ error: 'Título e conteúdo são obrigatórios' });
        
        const articleData = {
            title,
            content,
            category: category || 'Geral',
            author: req.user._id
        };
        
        if (req.file) {
            articleData.coverImage = req.file.path;
        }
        
        const article = new Article(articleData);
        await article.save();
        res.status(201).json(article);
    } catch(err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/blog/articles', auth, async (req, res) => {
    try {
        const articles = await Article.find()
            .populate('author', 'username fullName avatar isFake')
            .sort({ createdAt: -1 });
        res.json(articles);
    } catch(err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/blog/articles/:id', auth, async (req, res) => {
    try {
        const article = await Article.findById(req.params.id)
            .populate('author', 'username fullName avatar isFake');
        if(!article) return res.status(404).json({ error: 'Matéria não encontrada' });
        
        article.views = (article.views || 0) + 1;
        await article.save();
        
        res.json(article);
    } catch(err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/blog/articles/:id', auth, async (req, res) => {
    try {
        const article = await Article.findById(req.params.id);
        if(!article) return res.status(404).json({ error: 'Matéria não encontrada' });
        
        if(String(article.author) !== String(req.user._id)) {
            return res.status(403).json({ error: 'Sem permissão para deletar' });
        }
        
        await article.deleteOne();
        res.json({ success: true });
    } catch(err) {
        res.status(500).json({ error: err.message });
    }
});

// Socket.io Real-time
io.on('connection', (socket) => {
    console.log('User connected:', socket.id);
    
    socket.on('join', (userId) => {
        socket.join(userId);
    });

    socket.on('sendMessage', async (data) => {
        try {
            const { content, token, receiver, conversationId } = data;
            if (!token) return;
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const senderId = decoded.id;

            // Check censorship
            const sender = await User.findById(senderId);
            if (sender && !sender.canSendDMs) {
                return socket.emit('error', { message: 'Você está impossibilitado de enviar mensagens pelo administrador.' });
            }

            let conv;
            if (conversationId) {
                conv = await Conversation.findById(conversationId);
            } else if (receiver) {
                // Find or create 1-on-1 conversation
                conv = await Conversation.findOne({ 
                    participants: { $all: [senderId, receiver] },
                    isGroup: { $ne: true } 
                });
                
                if (!conv) {
                    conv = new Conversation({
                        participants: [senderId, receiver],
                        isGroup: false
                    });
                    await conv.save();
                }
            }

            if (!conv) return;

            const msg = new Message({ 
                sender: senderId, 
                receiver: conversationId ? null : (receiver || conv.participants.find(p => p.toString() !== senderId.toString())), 
                conversationId: conv._id,
                content 
            });
            await msg.save();

            // Update conversation last message
            conv.lastMessage = {
                content: content,
                sender: senderId,
                createdAt: new Date()
            };
            await conv.save();

            const msgWithSender = await Message.findById(msg._id).populate('sender', 'username avatar');
            const formattedMsg = msgWithSender.toObject();
            formattedMsg.sender_details = msgWithSender.sender;

            // Emit to all participants
            if (conv.participants) {
                conv.participants.forEach(pId => {
                    if (pId) {
                        const room = String(pId);
                        io.to(room).emit('newMessage', formattedMsg);
                        if (room !== String(senderId)) {
                            io.to(room).emit('incomingMessage', { senderId, conversationId: String(conv._id) });
                        }
                    }
                });
            }
        } catch (err) {
            console.error('Socket SendMessage Error:', err);
        }
    });

    socket.on('typing', async (data) => {
        try {
            const { conversationId, receiverId, senderId } = data;
            if (!senderId) return;
            if (conversationId) {
                const conv = await Conversation.findById(conversationId);
                if (conv && conv.participants) {
                    conv.participants.forEach(pId => {
                        if (pId && String(pId) !== String(senderId)) {
                            io.to(String(pId)).emit('userTyping', { senderId, conversationId });
                        }
                    });
                }
            } else if (receiverId) {
                socket.to(String(receiverId)).emit('userTyping', { senderId });
            }
        } catch (err) { console.error('Typing socket error:', err); }
    });

    socket.on('stopTyping', async (data) => {
        try {
            const { conversationId, receiverId, senderId } = data;
            if (!senderId) return;
            if (conversationId) {
                const conv = await Conversation.findById(conversationId);
                if (conv && conv.participants) {
                    conv.participants.forEach(pId => {
                        if (pId && String(pId) !== String(senderId)) {
                            io.to(String(pId)).emit('userStopTyping', { senderId, conversationId });
                        }
                    });
                }
            } else if (receiverId) {
                socket.to(String(receiverId)).emit('userStopTyping', { senderId });
            }
        } catch (err) { console.error('StopTyping socket error:', err); }
    });

    socket.on('disconnect', () => {
        console.log('User disconnected');
    });
});

// Catch-all for SPA
app.get('/*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3004;
server.listen(PORT, () => {
  console.log('\n--- PHOTOFEED SERVER BOOTING (v4) ---');
  console.log(`Time: ${new Date().toISOString()}`);
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log('✅ Connected to MongoDB Atlas');
  console.log('🤖 AI Model: llama-3.3-70b-versatile');
});
