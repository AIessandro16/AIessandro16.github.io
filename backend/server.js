const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const db = new Database(path.resolve(process.cwd(), process.env.DB_PATH || 'evolva.sqlite'));
const SESSION_SECRET = process.env.SESSION_SECRET || '';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const SESSION_DURATION = 8 * 60 * 60 * 1000;
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS contact_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    business TEXT,
    service TEXT NOT NULL,
    message TEXT NOT NULL,
    consent INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )
  ;
  CREATE TABLE IF NOT EXISTS revoked_sessions (
    id TEXT PRIMARY KEY,
    revoked_at TEXT NOT NULL DEFAULT (datetime('now'))
  )
`);
const insertRequest = db.prepare(`
  INSERT INTO contact_requests (name, email, business, service, message, consent)
  VALUES (@name, @email, @business, @service, @message, @consent)
`);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      ...helmet.contentSecurityPolicy.getDefaultDirectives(),
      'style-src': ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      'font-src': ["'self'", 'https://fonts.gstatic.com', 'data:']
    }
  }
}));
app.use(express.json({ limit: '15kb' }));
app.use(express.static(path.join(__dirname, '../frontend')));
app.use((req, res, next) => {
  const origin = process.env.FRONTEND_ORIGIN;
  if (origin && req.headers.origin === origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
const contactLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5, standardHeaders: true, legacyHeaders: false });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5, standardHeaders: true, legacyHeaders: false });
const aiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });

function sign(value) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('base64url');
}

function createSession() {
  const payload = Buffer.from(JSON.stringify({ expires: Date.now() + SESSION_DURATION, id: crypto.randomBytes(16).toString('hex') })).toString('base64url');
  return `${payload}.${sign(payload)}`;
}

function getSession(req) {
  if (!SESSION_SECRET) return false;
  const token = String(req.headers.authorization || '').match(/^Bearer\s+(.+)$/i)?.[1];
  if (!token) return false;
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return false;
  const expected = sign(payload);
  const receivedBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);
  if (receivedBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(receivedBuffer, expectedBuffer)) return false;
  try {
    const session = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (!session.id || session.expires <= Date.now()) return false;
    if (db.prepare('SELECT 1 FROM revoked_sessions WHERE id = ?').get(session.id)) return false;
    return session;
  } catch {
    return false;
  }
}

function isAuthenticated(req) {
  return Boolean(getSession(req));
}

function requireAdmin(req, res, next) {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: 'Inicia sesión para continuar.' });
  req.adminSession = session;
  next();
}

app.post('/api/contact', contactLimiter, (req, res) => {
  const body = req.body || {};
  const name = String(body.name || '').trim();
  const email = String(body.email || '').trim();
  const business = String(body.business || '').trim();
  const service = String(body.service || '').trim();
  const message = String(body.message || '').trim();
  const consent = body.consent === true || body.consent === 'on';

  if (!name || name.length > 100) return res.status(400).json({ error: 'Revisa el nombre.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 200) return res.status(400).json({ error: 'Revisa el correo electrónico.' });
  if (business.length > 120) return res.status(400).json({ error: 'El nombre del negocio es demasiado largo.' });
  if (!service || service.length > 160) return res.status(400).json({ error: 'Selecciona un servicio.' });
  if (message.length < 10 || message.length > 2000) return res.status(400).json({ error: 'El mensaje debe tener entre 10 y 2000 caracteres.' });
  if (!consent) return res.status(400).json({ error: 'Necesitamos tu consentimiento para responder a la consulta.' });

  try {
    const result = insertRequest.run({ name, email, business, service, message, consent: 1 });
    return res.status(201).json({ ok: true, id: result.lastInsertRowid });
  } catch (error) {
    console.error('No se pudo guardar la consulta:', error.message);
    return res.status(500).json({ error: 'No se pudo guardar la consulta.' });
  }
});

app.post('/api/admin/login', loginLimiter, (req, res) => {
  if (!ADMIN_PASSWORD || !SESSION_SECRET) return res.status(503).json({ error: 'El acceso administrador todavía no está configurado.' });
  const submitted = Buffer.from(String(req.body?.password || ''));
  const expected = Buffer.from(ADMIN_PASSWORD);
  const valid = submitted.length === expected.length && crypto.timingSafeEqual(submitted, expected);
  if (!valid) return res.status(401).json({ error: 'La contraseña no es correcta.' });
  return res.json({ ok: true, token: createSession() });
});

app.get('/api/admin/session', (req, res) => res.json({ authenticated: isAuthenticated(req) }));

app.post('/api/admin/logout', (req, res) => {
  const session = getSession(req);
  if (session) db.prepare('INSERT OR IGNORE INTO revoked_sessions (id) VALUES (?)').run(session.id);
  return res.json({ ok: true });
});

app.get('/api/admin/contacts', requireAdmin, (_req, res) => {
  const rows = db.prepare(`SELECT id, name, email, business, service, message, created_at FROM contact_requests ORDER BY created_at DESC, id DESC LIMIT 200`).all();
  return res.json({ contacts: rows });
});

app.post('/api/assistant', aiLimiter, async (req, res) => {
  const message = String(req.body?.message || '').trim();
  if (message.length < 2 || message.length > 500) return res.status(400).json({ error: 'Escribe un mensaje de 2 a 500 caracteres.' });
  if (!process.env.GEMINI_API_KEY) return res.status(503).json({ error: 'El asistente estará disponible cuando se configure la clave de IA.' });

  const instructions = `Eres Evol, el asistente digital de EVOLVA, un emprendimiento ecuatoriano que ayuda a pequeños negocios a crecer digitalmente. Responde en español, con calidez, claridad y máximo 100 palabras. Conoce los servicios y tarifas actuales: Diagnóstico digital $35, Logotipo esencial $75, Identidad visual básica $160, Kit de contenido $55, Landing page $250, Estrategia digital inicial $90, plan Inicio $120/mes, Crecimiento $220/mes y Presencia Plus $300/mes. Los combos son Arranque de marca $199 y Presencia digital $279. Los precios son referenciales y costes externos se cotizan aparte. Ayuda a orientar al cliente y recomienda un siguiente paso, sin prometer resultados comerciales ni inventar servicios o precios. Para contratar, invítale a usar el formulario de contacto del sitio. No solicites contraseñas ni datos sensibles.`;
  try {
    const upstream = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${process.env.GEMINI_MODEL || 'gemini-2.5-flash'}:generateContent`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': process.env.GEMINI_API_KEY },
      body: JSON.stringify({ systemInstruction: { parts: [{ text: instructions }] }, contents: [{ role: 'user', parts: [{ text: message }] }], generationConfig: { maxOutputTokens: 220, temperature: 0.5 } }),
      signal: AbortSignal.timeout(20000)
    });
    if (!upstream.ok) throw new Error(`Proveedor de IA respondió ${upstream.status}`);
    const data = await upstream.json();
    const answer = data.candidates?.[0]?.content?.parts?.map((part) => part.text || '').join('').trim();
    if (!answer) throw new Error('Respuesta vacía de IA');
    return res.json({ answer });
  } catch (error) {
    console.error('No se pudo generar respuesta de IA:', error.message);
    return res.status(502).json({ error: 'El asistente no pudo responder ahora. Inténtalo de nuevo en un momento.' });
  }
});

app.get('/api/health', (_req, res) => res.json({ ok: true }));
app.listen(PORT, () => console.log(`EVOLVA listo en http://localhost:${PORT}`));
