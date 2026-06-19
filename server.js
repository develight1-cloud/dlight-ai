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
// Use ADMIN_SECRET (Render) as requested; fall back to ADMIN_SECRET_KEY for compatibility
const ADMIN_SECRET = process.env.ADMIN_SECRET || process.env.ADMIN_SECRET_KEY || null;
const FLW_SECRET_HASH = process.env.FLW_SECRET_HASH || null;
const DATABASE_URL = process.env.DATABASE_URL || null;
const JWT_SECRET = process.env.JWT_SECRET || null; // secret used to sign admin and user JWTs
const ADMIN_JWT_EXPIRES = process.env.ADMIN_JWT_EXPIRES || '15m';
const USER_JWT_EXPIRES = process.env.USER_JWT_EXPIRES || '7d';

if (!DATABASE_URL) {
  console.error('DATABASE_URL is not set. Exiting.');
  process.exit(1);
}
if (!JWT_SECRET) {
  console.warn('JWT_SECRET not set. Admin and user login will not work until JWT_SECRET is configured.');
}

// Create a Postgres pool
const pool = new Pool({
  connectionString: DATABASE_URL,
  // Uncomment and adjust SSL if your provider requires it (e.g. Heroku/Render):
  // ssl: { rejectUnauthorized: false }
});

// Initialize DB: create tables if they don't exist
const initDb = async () => {
  // transactions table (existing)
  const createTransactions = `
  CREATE TABLE IF NOT EXISTS transactions (
    id SERIAL PRIMARY KEY,
    tx_ref TEXT UNIQUE,
    flw_ref TEXT,
    amount NUMERIC,
    currency TEXT,
    status TEXT,
    customer_email TEXT,
    received_at TIMESTAMP WITH TIME ZONE,
    raw_payload JSONB
  );
  `;

  const createUsers = `
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    plan TEXT,
    credits INTEGER DEFAULT 0,
    videos_generated INTEGER DEFAULT 0,
    subscription_status TEXT DEFAULT 'inactive',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
  );
  `;

  const createVideoHistory = `
  CREATE TABLE IF NOT EXISTS video_history (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    prompt TEXT,
    duration_seconds INTEGER,
    credits_used INTEGER,
    video_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
  );
  `;

  await pool.query(createTransactions);
  await pool.query(createUsers);
  await pool.query(createVideoHistory);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_transactions_received_at ON transactions(received_at DESC);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_video_history_user_id ON video_history(user_id);`);
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

// Helper: check if request is admin
const isRequestAdmin = (req) => {
  // check admin_key in body
  const adminKey = req.body && req.body.admin_key ? String(req.body.admin_key) : null;
  if (adminKey && ADMIN_SECRET && adminKey === ADMIN_SECRET) return true;

  // check Authorization header for admin token
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];
  if (!authHeader) return false;
  const parts = String(authHeader).split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return false;
  const token = parts[1];
  const decoded = verifyJwtToken(token);
  if (decoded && decoded.role === 'admin') return true;
  return false;
};

// Middleware: protect admin routes with JWT
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

// Middleware: authenticate user JWT and attach user record
const authenticateUser = async (req, res, next) => {
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Missing Authorization header' });
  const parts = String(authHeader).split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid Authorization header format' });
  const token = parts[1];
  if (!JWT_SECRET) return res.status(500).json({ error: 'Server not configured with JWT_SECRET' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded || decoded.role !== 'user' || !decoded.user_id) return res.status(403).json({ error: 'Forbidden' });
    // fetch user from DB
    const userRes = await pool.query('SELECT id, email, plan, credits, videos_generated, subscription_status, created_at FROM users WHERE id = $1', [decoded.user_id]);
    if (userRes.rowCount === 0) return res.status(401).json({ error: 'User not found' });
    req.user = userRes.rows[0];
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// AI Mock Generation Route (legacy) - kept for compatibility
app.post('/api/generate', (req, res) => {
  const { prompt, duration, style } = req.body;
  if (!prompt) return res.status(400).json({ error: 'Prompt is required' });

  const sampleVideoUrl = 'https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ForBiggerBlazes.mp4';
  setTimeout(() => res.json({ success: true, video_url: sampleVideoUrl }), 3000);
});

// Helper: parse duration (accept '5s', '10s' or numeric seconds)
const parseDurationSeconds = (d) => {
  if (d == null) return null;
  if (typeof d === 'string') {
    const m = d.match(/^(\d+)s$/i);
    if (m) return parseInt(m[1], 10);
    const n = parseInt(d, 10);
    if (!isNaN(n)) return n;
  }
  if (typeof d === 'number') return d;
  return null;
};

// Credit cost mapping
const CREDIT_COST = {
  5: 5,
  10: 10,
  30: 30,
  60: 60
};

// Plan credits mapping
const PLAN_CREDITS = {
  'Standard': 150,
  'Ultra': 500
};

// generate-video: require user JWT and sufficient credits, unless admin bypass
app.post('/api/generate-video', async (req, res) => {
  const { prompt, duration, style, email } = req.body;
  if (!prompt) return res.status(400).json({ error: 'Prompt is required' });

  // Admin bypass
  if (isRequestAdmin(req)) {
    const adminVideoUrl = 'https://www.w3schools.com/html/mov_bbb.mp4';
    return res.json({ success: true, video_url: adminVideoUrl, bypass: true });
  }

  // Authenticate user
  try {
    // use authenticateUser middleware logic here manually to keep single handler behaviour
    const authHeader = req.headers['authorization'] || req.headers['Authorization'];
    if (!authHeader) return res.status(401).json({ error: 'Missing Authorization header' });
    const parts = String(authHeader).split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid Authorization header format' });
    const token = parts[1];
    if (!JWT_SECRET) return res.status(500).json({ error: 'Server not configured with JWT_SECRET' });
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (e) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    if (!decoded || decoded.role !== 'user' || !decoded.user_id) return res.status(403).json({ error: 'Forbidden' });

    const userId = decoded.user_id;

    // parse duration into seconds
    const durMatch = String(duration).match(/^(\d+)s$/i);
    const durationSeconds = durMatch ? parseInt(durMatch[1], 10) : parseInt(duration, 10);
    if (!durationSeconds || !CREDIT_COST[durationSeconds]) return res.status(400).json({ error: 'Unsupported duration' });
    const cost = CREDIT_COST[durationSeconds];

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // lock user row FOR UPDATE to avoid race conditions
      const userRow = await client.query('SELECT id, credits, videos_generated, subscription_status FROM users WHERE id = $1 FOR UPDATE', [userId]);
      if (userRow.rowCount === 0) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'User not found' });
      }
      const user = userRow.rows[0];

      if (user.credits < cost) {
        await client.query('ROLLBACK');
        return res.status(402).json({ error: 'Insufficient credits' });
      }

      // Update user and insert history
      const newUserRes = await client.query(
        'UPDATE users SET credits = credits - $1, videos_generated = videos_generated + 1 WHERE id = $2 RETURNING credits, videos_generated',
        [cost, userId]
      );
      const updated = newUserRes.rows[0];

      // Insert history
      const sampleVideoUrl = 'https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ForBiggerBlazes.mp4';
      await client.query(
        `INSERT INTO video_history (user_id, prompt, duration_seconds, credits_used, video_url) VALUES ($1, $2, $3, $4, $5)`,
        [userId, prompt, durationSeconds, cost, sampleVideoUrl]
      );

      await client.query('COMMIT');

      // simulate processing delay for UX
      setTimeout(() => {
        return res.json({
          success: true,
          video_url: sampleVideoUrl,
          credits_remaining: updated.credits,
          videos_generated: updated.videos_generated
        });
      }, 2000);

    } catch (err) {
      await client.query('ROLLBACK');
      console.error('Error in generate-video transaction:', err);
      return res.status(500).json({ error: 'Server error' });
    } finally {
      client.release();
    }

  } catch (err) {
    console.error('Error in generate-video:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Admin login: exchange admin_key for a short-lived JWT
app.post('/api/admin/login', (req, res) => {
  const { admin_key } = req.body;
  if (!admin_key) return res.status(400).json({ error: 'admin_key is required' });
  if (!ADMIN_SECRET) return res.status(500).json({ error: 'Server not configured with ADMIN_SECRET' });
  if (String(admin_key) !== String(ADMIN_SECRET)) return res.status(401).json({ error: 'Invalid admin credentials' });
  if (!JWT_SECRET) return res.status(500).json({ error: 'Server not configured with JWT_SECRET' });

  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: ADMIN_JWT_EXPIRES });
  return res.json({ token, expires_in: ADMIN_JWT_EXPIRES });
});

// User auth: simple email login to issue JWT (production: replace with secure auth)
app.post('/api/auth/login', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });
  if (!JWT_SECRET) return res.status(500).json({ error: 'Server not configured with JWT_SECRET' });

  try {
    // find or create user
    const userRes = await pool.query('SELECT id, email, plan, credits, videos_generated, subscription_status FROM users WHERE email = $1', [email.toLowerCase()]);
    let user;
    if (userRes.rowCount === 0) {
      const insert = await pool.query('INSERT INTO users (email, plan, credits, subscription_status) VALUES ($1, $2, $3, $4) RETURNING id, email, plan, credits, videos_generated, subscription_status', [email.toLowerCase(), null, 0, 'inactive']);
      user = insert.rows[0];
    } else {
      user = userRes.rows[0];
    }

    const token = jwt.sign({ role: 'user', user_id: user.id, email: user.email }, JWT_SECRET, { expiresIn: USER_JWT_EXPIRES });
    return res.json({ token, user: { id: user.id, email: user.email, plan: user.plan, credits: user.credits, subscription_status: user.subscription_status } });
  } catch (err) {
    console.error('Auth login error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
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
  const status = (data.status ?? payload.status ?? '').toString();
  const customerEmail = (data.customer && (data.customer.email || data.customer.email_address)) || data.customer_email || payload.customer_email || null;

  try {
    // Persist transaction idempotently
    const insertSql = `
      INSERT INTO transactions (tx_ref, flw_ref, amount, currency, status, customer_email, received_at, raw_payload)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      ON CONFLICT (tx_ref) DO NOTHING
      RETURNING id;
    `;
    const receivedAt = new Date().toISOString();
    const result = await pool.query(insertSql, [tx_ref, flw_ref, amount, currency, status, customerEmail, receivedAt, payload]);

    // If payment successful and we have email, attempt to update user's subscription
    if ((status === 'successful' || status === 'completed' || status === 'success') && customerEmail) {
      // Attempt to extract plan from payload metadata or tx_ref
      let plan = null;
      if (data.meta && data.meta.plan) plan = data.meta.plan;
      if (!plan && data.meta && data.meta.plan_name) plan = data.meta.plan_name;
      if (!plan && data.plan) plan = data.plan;
      if (!plan && data.custom_fields && Array.isArray(data.custom_fields)) {
        const f = data.custom_fields.find(cf => cf.name && /plan/i.test(cf.name));
        if (f) plan = f.value;
      }
      // Try parse from tx_ref patterns like '...-STANDARD-' or '...-ULTRA-'
      if (!plan && tx_ref) {
        const up = tx_ref.toUpperCase();
        if (up.includes('STANDARD')) plan = 'Standard';
        if (up.includes('ULTRA')) plan = 'Ultra';
      }

      // Normalize plan
      if (plan) {
        plan = String(plan).trim();
        if (/standard/i.test(plan)) plan = 'Standard';
        if (/ultra/i.test(plan)) plan = 'Ultra';
      }

      if (plan && PLAN_CREDITS[plan]) {
        // Upsert user: set plan, assign credits, set subscription_status active
        const emailLower = customerEmail.toLowerCase();
        const creditsForPlan = PLAN_CREDITS[plan];
        const upsertSql = `
          INSERT INTO users (email, plan, credits, subscription_status)
          VALUES ($1, $2, $3, 'active')
          ON CONFLICT (email) DO UPDATE SET plan = EXCLUDED.plan, credits = EXCLUDED.credits, subscription_status = 'active'
          RETURNING id, email, plan, credits, subscription_status;
        `;
        try {
          const upres = await pool.query(upsertSql, [emailLower, plan, creditsForPlan]);
          console.log('Updated user subscription from webhook:', upres.rows[0]);
        } catch (err) {
          console.error('Error upserting user on webhook:', err);
        }
      } else if (customerEmail) {
        // Ensure user exists with email but no plan change
        try {
          await pool.query(`INSERT INTO users (email) VALUES ($1) ON CONFLICT (email) DO NOTHING`, [customerEmail.toLowerCase()]);
        } catch (err) {
          console.error('Error ensuring user exists after webhook:', err);
        }
      }
    }

    if (result.rowCount === 0) {
      // duplicate
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

// User dashboard - authenticated
app.get('/api/user/dashboard', authenticateUser, async (req, res) => {
  try {
    const u = req.user;
    return res.json({ plan: u.plan, credits: u.credits, videos_generated: u.videos_generated, subscription_status: u.subscription_status });
  } catch (err) {
    console.error('Error in user dashboard:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// User history - authenticated
app.get('/api/user/history', authenticateUser, async (req, res) => {
  try {
    const rows = await pool.query(`SELECT id, prompt, duration_seconds, credits_used, video_url, created_at FROM video_history WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1000`, [req.user.id]);
    return res.json({ count: rows.rowCount, history: rows.rows });
  } catch (err) {
    console.error('Error fetching user history:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Fallback to serve index.html for all pages
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`DLiGHT AI Server running on port ${PORT}`);
});
