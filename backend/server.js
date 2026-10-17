const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const db = new DatabaseSync(path.resolve(process.cwd(), process.env.DB_PATH || 'evolva.sqlite'));
const SESSION_SECRET = process.env.SESSION_SECRET || '';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const SESSION_DURATION = 8 * 60 * 60 * 1000;
db.exec('PRAGMA journal_mode = WAL');
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
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
const contactLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5, standardHeaders: true, legacyHeaders: false });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5, standardHeaders: true, legacyHeaders: false });
const aiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false, message: { error: 'Has enviado varias preguntas seguidas. Espera un minuto y vuelve a intentarlo.' } });

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

app.delete('/api/admin/contacts/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'La solicitud indicada no es válida.' });
  const result = db.prepare('DELETE FROM contact_requests WHERE id = ?').run(id);
  if (!result.changes) return res.status(404).json({ error: 'La solicitud ya no existe.' });
  return res.json({ ok: true });
});

app.post('/api/assistant', aiLimiter, async (req, res) => {
  const message = String(req.body?.message || '').trim();
  if (message.length < 2 || message.length > 500) return res.status(400).json({ error: 'Escribe un mensaje de 2 a 500 caracteres.' });
  if (!process.env.GEMINI_API_KEY) return res.status(503).json({ error: 'El asistente estará disponible cuando se configure la clave de IA.' });

  const history = Array.isArray(req.body?.history)
    ? req.body.history.slice(-8)
      .map((item) => {
        if (item?.role === 'user' && typeof item.text === 'string') {
          return { role: 'user', parts: [{ text: item.text.slice(0, 1000) }] };
        }
        if (item?.role === 'assistant' && Array.isArray(item.parts)) {
          const parts = item.parts.slice(0, 4).map((part) => {
            const safePart = {};
            if (typeof part?.text === 'string') safePart.text = part.text.slice(0, 1200);
            if (typeof part?.thoughtSignature === 'string') safePart.thoughtSignature = part.thoughtSignature;
            if (typeof part?.thought === 'boolean') safePart.thought = part.thought;
            return safePart;
          }).filter((part) => Object.keys(part).length);
          return parts.length ? { role: 'model', parts } : null;
        }
        if (item?.role === 'assistant' && typeof item.text === 'string') {
          return { role: 'model', parts: [{ text: item.text.slice(0, 1000) }] };
        }
        return null;
      })
      .filter(Boolean)
    : [];
  const instructions = `Eres Evol, el asistente de EVOLVA, un pequeño negocio de Ecuador que ayuda a otros negocios con su imagen, sus redes sociales y sus páginas web. Hablas siempre en español, de forma amable y sencilla, como si explicaras las cosas a alguien que no trabaja en marketing.

AYUDA A LA PERSONA
Primero entiende qué negocio tiene, qué quiere mejorar y qué puede hacer ahora. Si falta un dato importante, haz una sola pregunta breve. Recomienda solo los servicios que tengan relación con lo que cuenta. Explica los términos técnicos con palabras comunes; por ejemplo, una página web sencilla es un lugar en internet donde el negocio presenta lo que ofrece y cómo contactarlo. Un calendario de publicaciones es una lista de qué publicar y cuándo.

SERVICIOS Y PRECIOS ACTUALES EN DÓLARES
Servicios puntuales: revisión del negocio en internet $25; diseño de logotipo $60; imagen de marca $125; diseños y textos para redes $45; página web para el negocio $200; plan de ideas para el negocio $70.
Community manager (manejo de redes): Inicio $99 al mes (8 publicaciones con textos, calendario sencillo, publicación en 1 red, respuestas a comentarios y mensajes hasta 15 minutos al día, 3 días por semana); Crecimiento $179 al mes (12 publicaciones, hasta 2 videos cortos editados con videos que entrega el cliente, 8 historias, publicación en hasta 2 redes y respuestas hasta 30 minutos al día, 3 días por semana); Presencia Plus $249 al mes (16 publicaciones, hasta 4 videos cortos editados con videos del cliente, 12 historias, hasta 2 redes y respuestas hasta 30 minutos diarios de lunes a viernes). No incluyen anuncios; ninguno ofrece atención permanente. Los planes se pagan al inicio del mes.
Paquetes: Imagen lista para publicar $175; Tu negocio en internet $205; Redes en marcha $195 el primer mes (plan Crecimiento más revisión inicial).
Estos son precios iniciales y el valor final se confirma antes de comenzar. Los costos de dirección y alojamiento de una página, anuncios, fotos e impresiones se pagan aparte y se acuerdan previamente. No inventes descuentos, tiempos, servicios ni entregables. No prometas ventas, seguidores ni resultados específicos.

FORMA DE RESPONDER
Usa de 2 a 5 frases, con un máximo de 120 palabras. Ve al punto y evita jerga. Si preguntan por precios, menciona los actuales tal como aparecen arriba. Si preguntan por el community manager, aclara que organiza y publica contenido y responde a la comunidad dentro del tiempo del plan; no contesta 24/7 ni cierra ventas por el negocio. Si quieren contratar, invítales a completar el formulario de contacto. No pidas contraseñas, claves, datos bancarios ni información sensible.`;
  try {
    const upstream = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${process.env.GEMINI_MODEL || 'gemini-3.8-flash'}:generateContent`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': process.env.GEMINI_API_KEY },
      body: JSON.stringify({ systemInstruction: { parts: [{ text: instructions }] }, contents: [...history, { role: 'user', parts: [{ text: message }] }], generationConfig: { maxOutputTokens: 1200, thinkingConfig: { thinkingLevel: 'low' } } }),
      signal: AbortSignal.timeout(20000)
    });
    if (!upstream.ok) {
      const providerError = await upstream.json().catch(() => ({}));
      const providerStatus = upstream.status;
      const providerCode = providerError.error?.status || '';
      console.error(`Gemini rechazó la solicitud: HTTP ${providerStatus}${providerCode ? ` (${providerCode})` : ''}`);
      let message = 'Gemini no pudo completar la respuesta. Inténtalo nuevamente en un momento.';
      if (providerStatus === 401 || providerStatus === 403) {
        message = 'Gemini rechazó el acceso. Revisa que la clave esté activa y tenga permisos para usar la API.';
      } else if (providerStatus === 429) {
        message = 'Gemini alcanzó su límite de uso o cuota. Espera un momento o revisa la cuota de la clave.';
      } else if (providerStatus === 404) {
        message = 'No se encontró el modelo de IA configurado. Revisa GEMINI_MODEL.';
      } else if (providerStatus === 400) {
        message = 'Gemini rechazó la solicitud. Revisa la configuración del modelo y el formato de la petición.';
      }
      return res.status(502).json({ error: message, providerStatus });
    }
    const data = await upstream.json();
    const candidate = data.candidates?.[0];
    if (candidate?.finishReason === 'MAX_TOKENS') {
      return res.status(502).json({ error: 'La respuesta quedó incompleta. Prueba con una pregunta más corta y te responderé de nuevo.' });
    }
    if (['SAFETY', 'RECITATION', 'BLOCKLIST', 'PROHIBITED_CONTENT'].includes(candidate?.finishReason)) {
      return res.status(502).json({ error: 'No pude responder esa pregunta tal como está escrita. Intenta formularla de otra manera.' });
    }
    const answer = candidate?.content?.parts?.filter((part) => !part.thought).map((part) => part.text || '').join('').trim();
    if (!answer) throw new Error('Respuesta vacía de IA');
    return res.json({ answer, modelTurn: { parts: candidate.content?.parts || [{ text: answer }] } });
  } catch (error) {
    console.error('No se pudo generar respuesta de IA:', error.message);
    if (error.name === 'TimeoutError' || error.name === 'AbortError') {
      return res.status(504).json({ error: 'La respuesta está tardando más de lo normal. Inténtalo otra vez en un momento.' });
    }
    if (error instanceof TypeError) {
      return res.status(502).json({ error: 'No pude conectar con el servicio de IA. Revisa tu conexión e inténtalo de nuevo.' });
    }
    return res.status(502).json({ error: 'El asistente no pudo responder ahora. Inténtalo de nuevo en un momento.' });
  }
});

app.get('/api/health', (_req, res) => res.json({ ok: true }));
app.listen(PORT, () => console.log(`EVOLVA listo en http://localhost:${PORT}`));
