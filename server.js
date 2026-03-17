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

const ttsLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { error: 'Troppe richieste audio. Aspetta un momento.' },
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS secrets (
      id          BIGSERIAL PRIMARY KEY,
      content     TEXT NOT NULL CHECK (char_length(content) BETWEEN 10 AND 500),
      category    VARCHAR(10) DEFAULT 's',
      ip_address  VARCHAR(100),
      device      TEXT,
      fingerprint JSONB,
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
    ALTER TABLE secrets ADD COLUMN IF NOT EXISTS fingerprint JSONB;
  `);
  console.log('✅ DB pronto');
}

// ── Parsing dispositivo ───────────────────────────────────────────────────────
function parseDevice(ua) {
  if (!ua) return 'Sconosciuto';
  let model = '', os = '', browser = '';
  const androidModel = ua.match(/\(Linux;.*?;\s*([^)]+?)\s+Build\//);
  if (androidModel) model = androidModel[1].trim();
  if (/iPhone/.test(ua)) { const v=ua.match(/iPhone OS ([\d_]+)/); os='iPhone'+(v?' iOS '+v[1].replace(/_/g,'.'):''); }
  else if (/iPad/.test(ua)) { const v=ua.match(/CPU OS ([\d_]+)/); os='iPad'+(v?' iPadOS '+v[1].replace(/_/g,'.'):''); }
  else if (/Android/.test(ua)) { const v=ua.match(/Android ([\d.]+)/); os=(model||'Android')+(v?' Android '+v[1]:''); }
  else if (/Windows NT/.test(ua)) { const m={'10.0':'10/11','6.3':'8.1','6.2':'8','6.1':'7'}; const v=ua.match(/Windows NT ([\d.]+)/); os='Windows '+(v?(m[v[1]]||v[1]):''); }
  else if (/Macintosh/.test(ua)) { const v=ua.match(/Mac OS X ([\d_]+)/); os='Mac'+(v?' '+v[1].replace(/_/g,'.'):''); }
  else os='Linux';
  if (/Arc\//.test(ua)) browser='Arc';
  else if (/Edg\//.test(ua)) { const v=ua.match(/Edg\/([\d]+)/); browser='Edge'+(v?' '+v[1]:''); }
  else if (/OPR\//.test(ua)) { const v=ua.match(/OPR\/([\d]+)/); browser='Opera'+(v?' '+v[1]:''); }
  else if (/Firefox\//.test(ua)) { const v=ua.match(/Firefox\/([\d]+)/); browser='Firefox'+(v?' '+v[1]:''); }
  else if (/Chrome\//.test(ua)) { const v=ua.match(/Chrome\/([\d]+)/); browser='Chrome'+(v?' '+v[1]:''); }
  else if (/Safari\//.test(ua)) { const v=ua.match(/Version\/([\d]+)/); browser='Safari'+(v?' '+v[1]:''); }
  else browser='Browser sconosciuto';
  return `${os} — ${browser}`;
}

// GET /api/secrets
app.get('/api/secrets', async (req, res) => {
  try {
    const limit  = Math.min(parseInt(req.query.limit) || 20, 50);
    const offset = parseInt(req.query.offset) || 0;
    const result = await pool.query(`
      SELECT s.id, s.content, s.category, s.created_at,
        COALESCE(json_object_agg(r.emoji, r.cnt) FILTER (WHERE r.emoji IS NOT NULL), '{}'::json) AS reactions
      FROM secrets s
      LEFT JOIN (SELECT secret_id, emoji, COUNT(*) as cnt FROM reactions GROUP BY secret_id, emoji) r ON r.secret_id = s.id
      GROUP BY s.id ORDER BY s.created_at DESC LIMIT $1 OFFSET $2
    `, [limit, offset]);
    const countResult = await pool.query('SELECT COUNT(*) FROM secrets');
    const total = parseInt(countResult.rows[0].count);
    res.json({ secrets: result.rows, total, hasMore: offset + limit < total });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Errore.' }); }
});

// POST /api/secrets
app.post('/api/secrets', postLimiter, async (req, res) => {
  try {
    const { content, category, fingerprint } = req.body;
    if (!content || typeof content !== 'string') return res.status(400).json({ error: 'Contenuto mancante.' });
    const trimmed = content.trim();
    if (trimmed.length < 10) return res.status(400).json({ error: 'Segreto troppo corto.' });
    if (trimmed.length > 500) return res.status(400).json({ error: 'Segreto troppo lungo.' });
    const allowed = ['s','p','c','d'];
    const cat = allowed.includes(category) ? category : 's';
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'sconosciuto';
    const device = parseDevice(req.headers['user-agent'] || '');
    const result = await pool.query(
      `INSERT INTO secrets (content, category, ip_address, device, fingerprint) VALUES ($1,$2,$3,$4,$5) RETURNING id, content, category, created_at`,
      [trimmed, cat, ip, device, fingerprint ? JSON.stringify(fingerprint) : null]
    );
    res.status(201).json({ ...result.rows[0], reactions: {} });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Errore.' }); }
});

// GET /api/voices — tutte le voci del account ElevenLabs
app.get('/api/voices', async (req, res) => {
  try {
    const apiKey = process.env.ELEVENLABS_KEY;
    if (!apiKey) return res.status(500).json({ error: 'Chiave non configurata.' });

    const response = await fetch('https://api.elevenlabs.io/v1/voices', {
      headers: { 'xi-api-key': apiKey }
    });

    if (!response.ok) {
      const err = await response.text();
      console.error('ElevenLabs voices error:', err);
      return res.status(500).json({ error: 'Errore ElevenLabs.' });
    }

    const data = await response.json();
    const voices = (data.voices || []).map(v => ({
      id: v.voice_id,
      name: v.name,
      category: v.category || '',
      labels: v.labels || {}
    }));

    res.json({ voices });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Errore nel recupero voci.' });
  }
});

// POST /api/tts — proxy TTS ElevenLabs
app.post('/api/tts', ttsLimiter, async (req, res) => {
  try {
    const { text, voice_id } = req.body;
    if (!text) return res.status(400).json({ error: 'Testo mancante.' });

    const apiKey = process.env.ELEVENLABS_KEY;
    if (!apiKey) return res.status(500).json({ error: 'Chiave ElevenLabs non configurata.' });

    // Voce di default: Rachel (premade, multilingua)
    const vid = voice_id || '21m00Tcm4TlvDq8ikWAM';

    const response = await fetch(`https://api.elevenlabs.io/v1/text-to-speech/${vid}`, {
      method: 'POST',
      headers: {
        'xi-api-key': apiKey,
        'Content-Type': 'application/json',
        'Accept': 'audio/mpeg',
      },
      body: JSON.stringify({
        text,
        model_id: 'eleven_multilingual_v2',
        voice_settings: { stability: 0.5, similarity_boost: 0.75 }
      })
    });

    if (!response.ok) {
      const err = await response.text();
      console.error('ElevenLabs TTS error:', err);
      return res.status(500).json({ error: 'Errore ElevenLabs.' });
    }

    const audioBuffer = await response.arrayBuffer();
    res.set('Content-Type', 'audio/mpeg');
    res.send(Buffer.from(audioBuffer));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Errore TTS.' });
  }
});

// POST /api/reactions
app.post('/api/reactions', async (req, res) => {
  try {
    const { secret_id, emoji } = req.body;
    if (!secret_id || !emoji) return res.status(400).json({ error: 'Dati mancanti.' });
    await pool.query(`INSERT INTO reactions (secret_id, emoji) VALUES ($1, $2)`, [secret_id, emoji]);
    const result = await pool.query(`SELECT emoji, COUNT(*) as cnt FROM reactions WHERE secret_id=$1 GROUP BY emoji`, [secret_id]);
    const reactions = {};
    result.rows.forEach(r => reactions[r.emoji] = parseInt(r.cnt));
    res.json({ reactions });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Errore.' }); }
});

// GET /api/stats
app.get('/api/stats', async (req, res) => {
  try {
    const result = await pool.query(`SELECT COUNT(*) AS total, COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') AS today FROM secrets`);
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: 'Errore.' }); }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend/public/index.html'));
});

initDB().then(() => {
  app.listen(PORT, () => console.log(`🌿 Lo Spiolo su http://localhost:${PORT}`));
});
