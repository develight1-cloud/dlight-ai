import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import crypto from 'crypto';
import { Pool } from 'pg';
import jwt from 'jsonwebtoken';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 5001;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Config / secrets
const ADMIN_SECRET = process.env.ADMIN_SECRET_KEY || null;
const FLW_SECRET_HASH = process.env.FLW_SECRET_HASH || null;
const DATABASE_URL = process.env.DATABASE_URL || null;
const JWT_SECRET = process.env.JWT_SECRET || null; // secret used to sign admin JWTs
const ADMIN_JWT_EXPIRES = process.env.ADMIN_JWT_EXPIRES || '15m';

if (!DATABASE_URL) {
  console.error('DATABASE_URL is not set. Exiting.');
  process.exit(1);
}
if (!JWT_SECRET) {
  console.warn('JWT_SECRET not set. Admin login will not work until JWT_SECRET is configured.');
}

// Create a Postgres pool
const pool = new Pool({
  connectionString: DATABASE_URL,
  // Uncomment and adjust SSL if your provider requires it (e.g. Heroku/Render):
  // ssl: { rejectUnauthorized: false }
});

// Initialize DB: create table if it doesn't exist
const initDb = async () => {
  const createTableSql = `
  CREATE TABLE IF NOT EXISTS transactions (
    id SERIAL PRIMARY KEY,
    tx_ref TEXT UNIQUE NOT NULL,
    flw_ref TEXT,
    amount NUMERIC,
    currency TEXT,
    status TEXT,
    customer_email TEXT,
    received_at TIMESTAMP WITH TIME ZONE,
    raw_payload JSONB
  );
  `;
  await pool.query(createTableSql);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_transactions_received_at ON transactions(received_at DESC);`);
};

initDb().catch((err) => {
  console.error('Failed to initialize DB:', err);
  process.exit(1);
});

// Helper: timing-safe compare for webhook secret
const verifyHeaderEquals = (incoming, expected) => {
  if (!incoming || !expected) return false;
  try {
    const incBuf = Buffer.from(String(incoming));
    const expBuf = Buffer.from(String(expected));
    if (incBuf.length !== expBuf.length) return false;
    return crypto.timingSafeEqual(incBuf, expBuf);
  } catch (e) {
    return false;
  }
};

// Helper: verify JWT, returns decoded payload or null
const verifyJwtToken = (token) => {
  if (!JWT_SECRET) return null;
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
};

// Helper: check if request is authorized as admin (either admin_key in body matches ADMIN_SECRET, or Authorization Bearer token is valid)
const isRequestAdmin = (req) => {
  // check admin_key in body
  const adminKey = req.body && req.body.admin_key ? String(req.body.admin_key) : null;
  if (adminKey && ADMIN_SECRET && adminKey === ADMIN_SECRET) return true;

  // check Authorization header
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];
  if (!authHeader) return false;
  const parts = String(authHeader).split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return false;
  const token = parts[1];
  const decoded = verifyJwtToken(token);
  if (decoded && decoded.role === 'admin') return true;
  return false;
};

// Middleware: protect routes with JWT (expects Authorization: Bearer <token>)
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Missing Authorization header' });
  const parts = String(authHeader).split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid Authorization header format' });
  const token = parts[1];
  if (!JWT_SECRET) return res.status(500).json({ error: 'Server not configured with JWT_SECRET' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded || decoded.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    req.admin = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// AI Mock Generation Route (legacy)
app.post('/api/generate', (req, res) => {
  const { prompt, duration, style } = req.body;
  if (!prompt) return res.status(400).json({ error: 'Prompt is required' });

  const sampleVideoUrl = 'https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ForBiggerBlazes.mp4';

  setTimeout(() => {
    return res.json({ success: true, video_url: sampleVideoUrl });
  }, 3000);
});

// generate-video with admin bypass via admin_key or valid JWT
app.post('/api/generate-video', (req, res) => {
  const { prompt } = req.body;
  if (!prompt) return res.status(400).json({ error: 'Prompt is required' });

  if (isRequestAdmin(req)) {
    const adminVideoUrl = 'https://www.w3schools.com/html/mov_bbb.mp4';
    return res.json({ success: true, video_url: adminVideoUrl, bypass: true });
  }

  const sampleVideoUrl = 'https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ForBiggerBlazes.mp4';
  setTimeout(() => {
    return res.json({ success: true, video_url: sampleVideoUrl });
  }, 3000);
});

// Admin login: exchange admin_key for a short-lived JWT
app.post('/api/admin/login', (req, res) => {
  const { admin_key } = req.body;
  if (!admin_key) return res.status(400).json({ error: 'admin_key is required' });
  if (!ADMIN_SECRET) return res.status(500).json({ error: 'Server not configured with ADMIN_SECRET_KEY' });
  if (String(admin_key) !== String(ADMIN_SECRET)) return res.status(401).json({ error: 'Invalid admin credentials' });
  if (!JWT_SECRET) return res.status(500).json({ error: 'Server not configured with JWT_SECRET' });

  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: ADMIN_JWT_EXPIRES });
  return res.json({ token, expires_in: ADMIN_JWT_EXPIRES });
});

// Return public configuration (public Flutterwave key)
app.get('/api/config', (req, res) => {
  return res.json({ flutterwave_public_key: process.env.FLW_PUBLIC_KEY || null });
});

// Proxy verification endpoints (use FLW_SECRET_KEY)
app.get('/api/verify/transaction/:id', async (req, res) => {
  const { id } = req.params;
  const secret = process.env.FLW_SECRET_KEY;
  if (!secret) return res.status(500).json({ error: 'Server not configured with FLW_SECRET_KEY' });
  try {
    const resp = await fetch(`https://api.flutterwave.com/v3/transactions/${encodeURIComponent(id)}/verify`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${secret}`, 'Content-Type': 'application/json' }
    });
    const data = await resp.json();
    return res.status(resp.status).json(data);
  } catch (err) {
    console.error('Error verifying transaction by id:', err);
    return res.status(502).json({ error: 'Failed to contact Flutterwave' });
  }
});

app.get('/api/verify', async (req, res) => {
  const { tx_ref } = req.query;
  const secret = process.env.FLW_SECRET_KEY;
  if (!tx_ref) return res.status(400).json({ error: 'tx_ref is required' });
  if (!secret) return res.status(500).json({ error: 'Server not configured with FLW_SECRET_KEY' });
  try {
    const resp = await fetch(`https://api.flutterwave.com/v3/transactions?tx_ref=${encodeURIComponent(tx_ref)}`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${secret}`, 'Content-Type': 'application/json' }
    });
    const data = await resp.json();
    return res.status(resp.status).json(data);
  } catch (err) {
    console.error('Error verifying transaction by tx_ref:', err);
    return res.status(502).json({ error: 'Failed to contact Flutterwave' });
  }
});

// Webhook verification and persistence to Postgres (protected by verif-hash)
app.post('/api/webhook/flutterwave', async (req, res) => {
  const incomingHash = req.headers['verif-hash'] || req.headers['verif_hash'] || req.headers['verification-hash'] || req.headers['x-verif-hash'];
  const expectedHash = FLW_SECRET_HASH;

  if (!expectedHash) {
    console.warn('FLW_SECRET_HASH not configured. Rejecting webhook.');
    return res.status(500).json({ error: 'Server webhook secret not configured' });
  }

  if (!verifyHeaderEquals(incomingHash, expectedHash)) {
    console.warn('Webhook signature verification failed. Rejecting.');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const payload = req.body || {};
  const data = payload.data || payload;

  const tx_ref = data.tx_ref || data.reference || data.flw_ref || payload.tx_ref || null;
  const flw_ref = data.flw_ref || data.flwRef || data.flwref || payload.flw_ref || null;
  const amount = data.amount ?? payload.amount ?? null;
  const currency = data.currency ?? payload.currency ?? null;
  const status = data.status ?? payload.status ?? null;
  const customerEmail = (data.customer && (data.customer.email || data.customer.email_address)) || data.customer_email || payload.customer_email || null;

  if (!tx_ref) {
    console.warn('Webhook payload missing tx_ref — cannot persist without idempotency key.');
    return res.status(400).json({ error: 'Missing tx_ref in webhook payload' });
  }

  try {
    const insertSql = `
      INSERT INTO transactions (tx_ref, flw_ref, amount, currency, status, customer_email, received_at, raw_payload)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      ON CONFLICT (tx_ref) DO NOTHING
      RETURNING id;
    `;
    const receivedAt = new Date().toISOString();
    const result = await pool.query(insertSql, [
      tx_ref,
      flw_ref,
      amount,
      currency,
      status,
      customerEmail,
      receivedAt,
      payload
    ]);

    if (result.rowCount === 0) {
      console.log(`Duplicate webhook for tx_ref=${tx_ref} detected; skipping insert.`);
      return res.status(200).json({ received: true, note: 'duplicate', tx_ref });
    }

    const insertedId = result.rows[0].id;
    console.log('Persisted verified transaction:', { id: insertedId, tx_ref });
    return res.status(200).json({ received: true, inserted_id: insertedId, tx_ref });
  } catch (err) {
    console.error('DB error while inserting transaction:', err);
    return res.status(500).json({ error: 'DB error' });
  }
});

// Admin endpoint – read rows from Postgres (protected by JWT middleware)
app.get('/api/admin/verified-transactions', authenticateJWT, async (req, res) => {
  try {
    const rows = await pool.query(`
      SELECT id, tx_ref, flw_ref, amount, currency, status, customer_email, received_at
      FROM transactions
      ORDER BY received_at DESC
      LIMIT 1000
    `);
    return res.json({ count: rows.rowCount, transactions: rows.rows });
  } catch (err) {
    console.error('Error querying transactions:', err);
    return res.status(500).json({ error: 'DB error' });
  }
});

// Fallback to serve index.html for all pages
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`DLiGHT AI Server running on port ${PORT}`);
});
