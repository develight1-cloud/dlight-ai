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

// AI Mock Generation Route
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

// Fallback to serve index.html for all pages
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`DLiGHT AI Server running on port ${PORT}`);
});
