require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'frontend/public')));

const postLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  message: { error: 'Troppi segreti in poco tempo. Aspetta un po\'.' },
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS secrets (
      id          BIGSERIAL PRIMARY KEY,
      content     TEXT NOT NULL CHECK (char_length(content) BETWEEN 10 AND 500),
      category    VARCHAR(10) DEFAULT 's',
      ip_address  VARCHAR(100),
      device      TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS reactions (
      id          BIGSERIAL PRIMARY KEY,
      secret_id   BIGINT REFERENCES secrets(id) ON DELETE CASCADE,
      emoji       VARCHAR(10) NOT NULL,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );
    ALTER TABLE secrets ADD COLUMN IF NOT EXISTS ip_address VARCHAR(100);
    ALTER TABLE secrets ADD COLUMN IF NOT EXISTS device TEXT;
  `);
  console.log('✅ DB pronto');
}

// ── Parsing dispositivo dettagliato ──────────────────────────────────────────
function parseDevice(ua) {
  if (!ua) return 'Sconosciuto';

  let model   = '';
  let os      = '';
  let osVer   = '';
  let browser = '';
  let bVer    = '';

  // ── Modello Android (es. "Samsung SM-G991B", "Xiaomi Redmi Note 11") ──
  const androidModel = ua.match(/\(Linux;.*?;\s*([^)]+?)\s+Build\//);
  if (androidModel) {
    model = androidModel[1].trim();
  }

  // ── OS ──
  if (/iPhone/.test(ua)) {
    model = 'iPhone';
    const v = ua.match(/iPhone OS ([\d_]+)/);
    osVer = v ? ' iOS ' + v[1].replace(/_/g, '.') : '';
    os = 'iPhone' + osVer;
  } else if (/iPad/.test(ua)) {
    model = 'iPad';
    const v = ua.match(/CPU OS ([\d_]+)/);
    osVer = v ? ' iPadOS ' + v[1].replace(/_/g, '.') : '';
    os = 'iPad' + osVer;
  } else if (/Android/.test(ua)) {
    const v = ua.match(/Android ([\d.]+)/);
    osVer = v ? ' Android ' + v[1] : ' Android';
    os = (model ? model : 'Android') + osVer;
  } else if (/Windows NT/.test(ua)) {
    const versions = {
      '10.0': '10/11', '6.3': '8.1', '6.2': '8',
      '6.1': '7', '6.0': 'Vista', '5.1': 'XP'
    };
    const v = ua.match(/Windows NT ([\d.]+)/);
    const winVer = v ? (versions[v[1]] || v[1]) : '';
    os = 'Windows ' + winVer;
  } else if (/Macintosh/.test(ua)) {
    const v = ua.match(/Mac OS X ([\d_]+)/);
    osVer = v ? ' ' + v[1].replace(/_/g, '.') : '';
    os = 'Mac' + osVer;
  } else if (/Linux/.test(ua)) {
    os = 'Linux';
  } else {
    os = 'Sconosciuto';
  }

  // ── Browser ──
  if (/Edg\//.test(ua)) {
    const v = ua.match(/Edg\/([\d.]+)/);
    browser = 'Edge' + (v ? ' ' + v[1].split('.')[0] : '');
  } else if (/OPR\//.test(ua)) {
    const v = ua.match(/OPR\/([\d.]+)/);
    browser = 'Opera' + (v ? ' ' + v[1].split('.')[0] : '');
  } else if (/Firefox\//.test(ua)) {
    const v = ua.match(/Firefox\/([\d.]+)/);
    browser = 'Firefox' + (v ? ' ' + v[1].split('.')[0] : '');
  } else if (/Chrome\//.test(ua)) {
    const v = ua.match(/Chrome\/([\d.]+)/);
    browser = 'Chrome' + (v ? ' ' + v[1].split('.')[0] : '');
  } else if (/Safari\//.test(ua) && !/Chrome/.test(ua)) {
    const v = ua.match(/Version\/([\d.]+)/);
    browser = 'Safari' + (v ? ' ' + v[1].split('.')[0] : '');
  } else {
    browser = 'Browser sconosciuto';
  }

  return `${os} — ${browser}`;
}

// GET /api/secrets — NON restituisce ip/device al frontend
app.get('/api/secrets', async (req, res) => {
  try {
    const limit  = Math.min(parseInt(req.query.limit) || 20, 50);
    const offset = parseInt(req.query.offset) || 0;

    const result = await pool.query(`
      SELECT s.id, s.content, s.category, s.created_at,
        COALESCE(
          json_object_agg(r.emoji, r.cnt) FILTER (WHERE r.emoji IS NOT NULL),
          '{}'::json
        ) AS reactions
      FROM secrets s
      LEFT JOIN (
        SELECT secret_id, emoji, COUNT(*) as cnt
        FROM reactions GROUP BY secret_id, emoji
      ) r ON r.secret_id = s.id
      GROUP BY s.id
      ORDER BY s.created_at DESC
      LIMIT $1 OFFSET $2
    `, [limit, offset]);

    const countResult = await pool.query('SELECT COUNT(*) FROM secrets');
    const total = parseInt(countResult.rows[0].count);

    res.json({ secrets: result.rows, total, hasMore: offset + limit < total });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Errore nel recupero dei segreti.' });
  }
});

// POST /api/secrets — salva IP e dispositivo dettagliato
app.post('/api/secrets', postLimiter, async (req, res) => {
  try {
    const { content, category } = req.body;
    if (!content || typeof content !== 'string') return res.status(400).json({ error: 'Contenuto mancante.' });
    const trimmed = content.trim();
    if (trimmed.length < 10) return res.status(400).json({ error: 'Segreto troppo corto (min 10 caratteri).' });
    if (trimmed.length > 500) return res.status(400).json({ error: 'Segreto troppo lungo (max 500 caratteri).' });

    const allowed = ['s','p','c','d'];
    const cat = allowed.includes(category) ? category : 's';

    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim()
             || req.socket.remoteAddress
             || 'sconosciuto';

    const ua = req.headers['user-agent'] || '';
    const device = parseDevice(ua);

    const result = await pool.query(
      `INSERT INTO secrets (content, category, ip_address, device)
       VALUES ($1, $2, $3, $4)
       RETURNING id, content, category, created_at`,
      [trimmed, cat, ip, device]
    );
    res.status(201).json({ ...result.rows[0], reactions: {} });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Errore nella pubblicazione.' });
  }
});

// POST /api/reactions
app.post('/api/reactions', async (req, res) => {
  try {
    const { secret_id, emoji } = req.body;
    if (!secret_id || !emoji) return res.status(400).json({ error: 'Dati mancanti.' });
    await pool.query(
      `INSERT INTO reactions (secret_id, emoji) VALUES ($1, $2)`,
      [secret_id, emoji]
    );
    const result = await pool.query(
      `SELECT emoji, COUNT(*) as cnt FROM reactions WHERE secret_id=$1 GROUP BY emoji`,
      [secret_id]
    );
    const reactions = {};
    result.rows.forEach(r => reactions[r.emoji] = parseInt(r.cnt));
    res.json({ reactions });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Errore nella reazione.' });
  }
});

// GET /api/stats
app.get('/api/stats', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT COUNT(*) AS total,
        COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') AS today
      FROM secrets
    `);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Errore stats.' });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend/public/index.html'));
});

initDB().then(() => {
  app.listen(PORT, () => console.log(`🌿 Lo Spiolo su http://localhost:${PORT}`));
});
