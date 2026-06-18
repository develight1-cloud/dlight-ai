import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 5001;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Admin secret (set via environment variable ADMIN_SECRET_KEY)
const ADMIN_SECRET = process.env.ADMIN_SECRET_KEY || null;

// In-memory store for verified transactions (prepare for later DB persistence)
const verifiedTransactions = [];

// AI Mock Generation Route (legacy)
app.post('/api/generate', (req, res) => {
    const { prompt, duration, style } = req.body;
    
    if (!prompt) {
        return res.status(400).json({ error: 'Prompt is required' });
    }

    const sampleVideoUrl = "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ForBiggerBlazes.mp4";

    setTimeout(() => {
        return res.json({
            success: true,
            video_url: sampleVideoUrl
        });
    }, 3000);
});

// New endpoint: generate-video with admin secret-key bypass
app.post('/api/generate-video', (req, res) => {
    const { prompt, duration, style, email, admin_key } = req.body;

    if (!prompt) {
        return res.status(400).json({ error: 'Prompt is required' });
    }

    // If admin_key is provided and matches server ADMIN_SECRET, bypass payment and return streaming test video
    if (admin_key && ADMIN_SECRET && String(admin_key) === String(ADMIN_SECRET)) {
        const adminVideoUrl = "https://www.w3schools.com/html/mov_bbb.mp4";
        return res.json({ success: true, video_url: adminVideoUrl, bypass: true });
    }

    // Default mock behavior for non-admins (simulate processing)
    const sampleVideoUrl = "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ForBiggerBlazes.mp4";

    setTimeout(() => {
        return res.json({
            success: true,
            video_url: sampleVideoUrl
        });
    }, 3000);
});

// Return public configuration (public Flutterwave key)
app.get('/api/config', (req, res) => {
    return res.json({
        flutterwave_public_key: process.env.FLW_PUBLIC_KEY || null
    });
});

// Verify a transaction by Flutterwave transaction ID
app.get('/api/verify/transaction/:id', async (req, res) => {
    const { id } = req.params;
    const secret = process.env.FLW_SECRET_KEY;

    if (!secret) return res.status(500).json({ error: 'Server not configured with FLW_SECRET_KEY' });

    try {
        const resp = await fetch(`https://api.flutterwave.com/v3/transactions/${encodeURIComponent(id)}/verify`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${secret}`,
                'Content-Type': 'application/json'
            }
        });

        const data = await resp.json();
        return res.status(resp.status).json(data);
    } catch (err) {
        console.error('Error verifying transaction by id:', err);
        return res.status(502).json({ error: 'Failed to contact Flutterwave' });
    }
});

// Verify a transaction by tx_ref (query param)
app.get('/api/verify', async (req, res) => {
    const { tx_ref } = req.query;
    const secret = process.env.FLW_SECRET_KEY;

    if (!tx_ref) return res.status(400).json({ error: 'tx_ref is required' });
    if (!secret) return res.status(500).json({ error: 'Server not configured with FLW_SECRET_KEY' });

    try {
        const resp = await fetch(`https://api.flutterwave.com/v3/transactions?tx_ref=${encodeURIComponent(tx_ref)}`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${secret}`,
                'Content-Type': 'application/json'
            }
        });

        const data = await resp.json();
        return res.status(resp.status).json(data);
    } catch (err) {
        console.error('Error verifying transaction by tx_ref:', err);
        return res.status(502).json({ error: 'Failed to contact Flutterwave' });
    }
});

// Simple webhook receiver for Flutterwave with signature verification
// Expects the header 'verif-hash' to match the environment variable FLW_SECRET_HASH
app.post('/api/webhook/flutterwave', (req, res) => {
    const incomingHash = req.headers['verif-hash'] || req.headers['verif_hash'] || req.headers['verification-hash'];
    const expectedHash = process.env.FLW_SECRET_HASH || null;

    if (!expectedHash) {
        console.warn('FLW_SECRET_HASH not configured on server. Rejecting webhook to avoid unauthorized processing.');
        return res.status(500).json({ error: 'Server webhook secret not configured' });
    }

    if (!incomingHash || String(incomingHash) !== String(expectedHash)) {
        console.warn('Received webhook with invalid or missing verif-hash header. Rejecting.');
        return res.status(401).json({ error: 'Unauthorized' });
    }

    // At this point the webhook is considered verified
    const payload = req.body || {};

    // Flexible extraction of transaction details from common Flutterwave webhook shapes
    const data = payload.data || payload;
    const tx_ref = data.tx_ref || data.reference || data.flw_ref || payload.tx_ref || null;
    const amount = data.amount || payload.amount || null;
    const status = data.status || payload.status || null;
    const customerEmail = (data.customer && (data.customer.email || data.customer.email_address)) || data.customer_email || payload.customer_email || null;

    const entry = {
        received_at: new Date().toISOString(),
        tx_ref,
        amount,
        customer_email: customerEmail,
        status,
        raw: payload
    };

    // Log to console and store in in-memory array for future DB integration
    console.log('Verified Flutterwave webhook received:', JSON.stringify(entry, null, 2));
    verifiedTransactions.push(entry);

    // Respond to Flutterwave quickly
    return res.status(200).json({ received: true });
});

// (Optional) Admin-only endpoint to view in-memory verified transactions (safe for testing only)
app.get('/api/admin/verified-transactions', (req, res) => {
    // Simple protection: require ADMIN_SECRET as query param or header to view (not for production)
    const auth = req.query.admin_key || req.headers['x-admin-key'];
    if (!ADMIN_SECRET || String(auth) !== String(ADMIN_SECRET)) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    return res.json({ count: verifiedTransactions.length, transactions: verifiedTransactions });
});

// Fallback to serve index.html for all pages
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`DLiGHT AI Server running on port ${PORT}`);
});
