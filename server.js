const express = require('express');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const jwt = require('jsonwebtoken');

// Load environment variables in development
if (process.env.NODE_ENV !== 'production') {
    try {
        require('dotenv').config();
    } catch (e) {
        console.log('dotenv not found, using environment variables');
    }
}

const app = express();
const PORT = process.env.PORT || 3000;

// Basic middleware
app.use(helmet());
app.use(express.json({ limit: '1mb' }));

// Simple CORS setup
app.use(cors({
    origin: true, // Allow all origins for now
    credentials: true
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: { error: 'Too many requests, please try again later.' }
});

// Apply rate limiting to key endpoints
app.use('/api/keys', limiter);

// ==========================================
// SECURE KEY STORAGE
// ==========================================

class SecureKeyStore {
    constructor() {
        // Generate or load master key
        this.masterKey = process.env.MASTER_KEY || this.generateSecureKey();
        
        if (!process.env.MASTER_KEY) {
            console.warn('⚠️ MASTER_KEY not set. Generated temporary key.');
        }
        
        // Your encryption keys
        this.encryptionKeys = {
            'auto-register': process.env.AUTO_REGISTER_KEY || 'oVPK+6WLFz1TwCJ9Sv8+zq8GaKIrHPDbzY5fqMOhmWU=',
            'remove-bind-card': process.env.REMOVE_BIND_KEY || 'z59A6ezEcj5HsVa1YqrXjJsdEKNkptDSulkG1hmq0WQ=',
            'xgame-mines': process.env.XGAME_MINES_KEY || 'kSS6LFYQu8yYmZUbRX61SJ0UU+DTXw7LiI808DWhg+U=',
            'no-ads': process.env.NO_ADS_KEY || 'OsvgWY7VoOlEq5HtcFykjBM8PpSPaxxenMzxY5P5HkU=',
            'launch-xgame': process.env.LAUNCH_XGAME_KEY || '8MrLj7l2P5kTeTNu97ULbQ/tkjpEWe78bxQem8FluwY='
        };
        
        console.log('🔐 Secure key store initialized with', Object.keys(this.encryptionKeys).length, 'keys');
    }
    
    generateSecureKey() {
        return crypto.randomBytes(32).toString('hex');
    }
    
    getKey(scriptType) {
        return this.encryptionKeys[scriptType] || null;
    }
    
    getAvailableScriptTypes() {
        return Object.keys(this.encryptionKeys);
    }
}

const keyStore = new SecureKeyStore();

// ==========================================
// AUTHENTICATION SYSTEM
// ==========================================

class AuthenticationManager {
    constructor() {
        this.jwtSecret = process.env.JWT_SECRET || this.generateSecureKey();
        
        if (!process.env.JWT_SECRET) {
            console.warn('⚠️ JWT_SECRET not set. Generated temporary secret.');
        }
        
        // Client secrets - make sure this matches your userscript
        this.clientSecrets = new Map();
        this.clientSecrets.set('aname-vip-client', process.env.CLIENT_SECRET || 'AN4M3XSCR4PT');
        this.clientSecrets.set('aname-dev-client', process.env.DEV_CLIENT_SECRET || 'dev-secret-123');
        
        if (!process.env.CLIENT_SECRET) {
            console.warn('⚠️ CLIENT_SECRET not set. Using default.');
        }
        
        console.log('🔑 Authentication manager initialized with', this.clientSecrets.size, 'clients');
    }
    
    generateSecureKey() {
        return crypto.randomBytes(32).toString('hex');
    }
    
    generateClientToken(clientId) {
        const payload = {
            clientId: clientId,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + (60 * 60) // 1 hour
        };
        
        return jwt.sign(payload, this.jwtSecret);
    }
    
    verifyClientSignature(clientId, timestamp, signature, nonce) {
        const clientSecret = this.clientSecrets.get(clientId);
        if (!clientSecret) {
            console.log('❌ Unknown client:', clientId);
            return false;
        }
        
        // Check timestamp (prevent replay attacks)
        const currentTime = Date.now();
        const requestTime = parseInt(timestamp);
        const timeDiff = Math.abs(currentTime - requestTime);
        
        // Allow 5 minute window
        if (timeDiff > 5 * 60 * 1000) {
            console.log('❌ Request timestamp too old:', timeDiff, 'ms');
            return false;
        }
        
        // Simple signature verification (you can make this more complex)
        const expectedSignature = crypto
            .createHmac('sha256', clientSecret)
            .update(`${clientId}:${timestamp}:${nonce}`)
            .digest('hex');
            
        return signature === expectedSignature;
    }
    
    verifyToken(token) {
        try {
            return jwt.verify(token, this.jwtSecret);
        } catch (error) {
            console.log('❌ Invalid JWT token:', error.message);
            return null;
        }
    }
}

const authManager = new AuthenticationManager();

// ==========================================
// MIDDLEWARE
// ==========================================

function authenticateRequest(req, res, next) {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Missing authorization header' });
        }
        
        const token = authHeader.substring(7);
        const decoded = authManager.verifyToken(token);
        
        if (!decoded) {
            return res.status(401).json({ error: 'Invalid token' });
        }
        
        req.clientId = decoded.clientId;
        next();
        
    } catch (error) {
        console.error('Auth error:', error);
        res.status(401).json({ error: 'Authentication failed' });
    }
}

// ==========================================
// ROUTES
// ==========================================

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        service: 'aname-key-server',
        version: '1.0.0',
        availableScripts: keyStore.getAvailableScriptTypes()
    });
});

// Authentication endpoint
app.post('/api/auth/token', (req, res) => {
    try {
        const { clientId, timestamp, signature, nonce } = req.body;
        
        console.log('🔑 Token request from:', clientId);
        
        if (!clientId || !timestamp || !signature || !nonce) {
            return res.status(400).json({ 
                error: 'Missing required fields',
                required: ['clientId', 'timestamp', 'signature', 'nonce']
            });
        }
        
        // Verify client signature
        if (!authManager.verifyClientSignature(clientId, timestamp, signature, nonce)) {
            return res.status(401).json({ error: 'Invalid client signature' });
        }
        
        // Generate JWT token
        const token = authManager.generateClientToken(clientId);
        
        console.log('✅ Token generated for:', clientId);
        
        res.json({
            token: token,
            expiresIn: 3600,
            clientId: clientId
        });
        
    } catch (error) {
        console.error('Auth error:', error);
        res.status(500).json({ error: 'Authentication failed' });
    }
});

// Key retrieval endpoint - Fixed route definition
app.post('/api/keys/:scriptType', authenticateRequest, (req, res) => {
    try {
        const scriptType = req.params.scriptType;
        const { timestamp, requestId } = req.body;
        
        console.log(`🔐 Key request for "${scriptType}" from client "${req.clientId}"`);
        
        // Validate script type
        const validScriptTypes = keyStore.getAvailableScriptTypes();
        if (!validScriptTypes.includes(scriptType)) {
            return res.status(400).json({ 
                error: 'Invalid script type',
                available: validScriptTypes
            });
        }
        
        // Get encryption key
        const encryptionKey = keyStore.getKey(scriptType);
        if (!encryptionKey) {
            return res.status(404).json({ error: 'Key not found' });
        }
        
        console.log(`✅ Key provided for "${scriptType}" to client "${req.clientId}"`);
        
        res.json({
            key: encryptionKey,
            scriptType: scriptType,
            expiresAt: Date.now() + (60 * 60 * 1000), // 1 hour
            requestId: requestId || 'no-id',
            clientId: req.clientId
        });
        
    } catch (error) {
        console.error('Key retrieval error:', error);
        res.status(500).json({ error: 'Key retrieval failed' });
    }
});

// Stats endpoint
app.get('/api/stats', authenticateRequest, (req, res) => {
    res.json({
        serverTime: new Date().toISOString(),
        uptime: Math.floor(process.uptime()),
        availableScripts: keyStore.getAvailableScriptTypes(),
        clientId: req.clientId
    });
});

// List available script types (public endpoint)
app.get('/api/scripts', (req, res) => {
    res.json({
        availableScripts: keyStore.getAvailableScriptTypes(),
        count: keyStore.getAvailableScriptTypes().length
    });
});

// ==========================================
// ERROR HANDLING
// ==========================================

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        error: 'Endpoint not found',
        path: req.originalUrl,
        availableEndpoints: [
            'GET /api/health',
            'GET /api/scripts',
            'POST /api/auth/token',
            'POST /api/keys/:scriptType',
            'GET /api/stats'
        ]
    });
});

// Global error handler
app.use((error, req, res, next) => {
    console.error('❌ Server error:', error);
    res.status(500).json({
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
    });
});

// ==========================================
// SERVER STARTUP
// ==========================================

const server = app.listen(PORT, () => {
    console.log('='.repeat(50));
    console.log('🚀 Aname Secure Key Server');
    console.log('='.repeat(50));
    console.log(`🌐 Server running on port ${PORT}`);
    console.log(`🔗 Health check: http://localhost:${PORT}/api/health`);
    console.log(`📅 Started at: ${new Date().toISOString()}`);
    console.log(`🔐 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log('='.repeat(50));
    
    // Test endpoints
    console.log('🧪 Available endpoints:');
    console.log(`   GET  http://localhost:${PORT}/api/health`);
    console.log(`   GET  http://localhost:${PORT}/api/scripts`);
    console.log(`   POST http://localhost:${PORT}/api/auth/token`);
    console.log(`   POST http://localhost:${PORT}/api/keys/:scriptType`);
    console.log(`   GET  http://localhost:${PORT}/api/stats`);
    console.log('='.repeat(50));
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('\n🛑 Received SIGTERM. Shutting down gracefully...');
    server.close(() => {
        console.log('✅ Server closed');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('\n🛑 Received SIGINT. Shutting down gracefully...');
    server.close(() => {
        console.log('✅ Server closed');
        process.exit(0);
    });
});

module.exports = app;