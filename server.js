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

// Admin bypass list
const ADMIN_EMAILS = ['david@davidsun.site'];

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

// New endpoint: generate-video with admin email bypass
app.post('/api/generate-video', (req, res) => {
    const { prompt, duration, style, email } = req.body;

    if (!prompt) {
        return res.status(400).json({ error: 'Prompt is required' });
    }

    // If the email is in the admin bypass list, immediately return the streaming-optimized test video
    if (email && ADMIN_EMAILS.includes(String(email).toLowerCase())) {
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

// Simple webhook receiver for Flutterwave (logs payload).
// NOTE: For production you should verify webhook signatures per Flutterwave docs.
app.post('/api/webhook/flutterwave', (req, res) => {
    console.log('Received Flutterwave webhook:', JSON.stringify(req.body));
    // Respond quickly to acknowledge receipt
    res.status(200).send('ok');
});

// Fallback to serve index.html for all pages
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`DLiGHT AI Server running on port ${PORT}`);
});
