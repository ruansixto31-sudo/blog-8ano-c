const mongoose = require('mongoose');

const postSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    media: [{ 
        url: String, 
        type: { type: String, enum: ['image', 'video'], default: 'image' },
        public_id: String
    }],
    caption: { type: String, default: '' },
    title: { type: String, default: '' },
    description: { type: String, default: '' },
    adminNote: { type: String, default: '' },
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    comments: [{
        user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        text: String,
        createdAt: { type: Date, default: Date.now }
    }],
    music: {
        title: String,
        artist: String,
        previewUrl: String
    },
    // Phase 9: Blog Builder Fields
    isBuilderBlog: { type: Boolean, default: false },
    groupName: { type: String, default: '' },
    participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    layout: { type: mongoose.Schema.Types.Mixed, default: [] },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Post', postSchema);
