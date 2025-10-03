import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import passport from 'passport';
import { Strategy as DiscordStrategy } from 'passport-discord';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node';
import { nanoid } from 'nanoid';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---- App base
const app = express();
const PORT = process.env.PORT || 3000;

// ---- DB (lowdb con archivo JSON)
const dbFile = path.join(__dirname, 'data', 'products.json');
fs.mkdirSync(path.dirname(dbFile), { recursive: true });
const adapter = new JSONFile(dbFile);
const db = new Low(adapter, { products: [] });
await db.read();
db.data ||= { products: [] };
await db.write();

// ---- Sesión
app.use(session({
  secret: process.env.SESSION_SECRET || 'cambia-esto',
  resave: false,
  saveUninitialized: false,
  cookie: {
    sameSite: 'lax',
    secure: false // pon true si usas HTTPS detrás de proxy
  }
}));

// ---- Passport Discord
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

passport.use(new DiscordStrategy({
  clientID: process.env.DISCORD_CLIENT_ID,
  clientSecret: process.env.DISCORD_CLIENT_SECRET,
  callbackURL: process.env.DISCORD_CALLBACK_URL,
  scope: ['identify']
}, (accessToken, refreshToken, profile, done) => {
  // profile.id es el ID de Discord
  return done(null, { id: profile.id, username: profile.username, avatar: profile.avatar });
}));

app.use(passport.initialize());
app.use(passport.session());

// ---- Middlewares
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ---- Archivos estáticos
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// ---- Helper de permisos
function isAuthed(req) { return !!req.user; }
function isAdmin(req) { return req.user && req.user.id === process.env.ADMIN_DISCORD_ID; }
function requireAdmin(req, res, next){
  if (!isAuthed(req)) return res.status(401).json({ error: 'No autenticado' });
  if (!isAdmin(req)) return res.status(403).json({ error: 'No autorizado' });
  next();
}

// ---- Auth rutas
app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback',
  passport.authenticate('discord', { failureRedirect: '/?login=failed' }),
  (req, res) => res.redirect('/?login=ok')
);
app.post('/auth/logout', (req, res) => {
  req.logout(() => {
    req.session.destroy(() => res.json({ ok: true }));
  });
});
app.get('/auth/me', (req, res) => {
  res.json({ user: req.user || null, isAdmin: isAdmin(req) });
});

// ---- Multer (subida de imágenes)
const uploadsDir = path.join(__dirname, 'uploads');
fs.mkdirSync(uploadsDir, { recursive: true });
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${Date.now()}-${nanoid(6)}${ext}`);
  }
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if(!file.mimetype.startsWith('image/')) return cb(new Error('Solo imágenes'), false);
    cb(null, true);
  },
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});

// ---- API pública (catálogo)
app.get('/api/products', async (req, res) => {
  await db.read();
  res.json({ products: db.data.products });
});

// ---- API admin (CRUD)
app.post('/api/products', requireAdmin, async (req, res) => {
  const { title, image, price, tag, desc, link } = req.body;
  if(!title || !image) return res.status(400).json({ error: 'title e image requeridos' });

  const product = {
    id: nanoid(),
    title,
    image,  // puede ser URL absoluta /uploads/xxx o cualquier URL
    price: price || '',
    tag: tag || '',
    desc: desc || '',
    link: link || process.env.PUBLIC_DISCORD_INVITE
  };
  await db.read();
  db.data.products.unshift(product);
  await db.write();
  res.json({ ok: true, product });
});

app.put('/api/products/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { title, image, price, tag, desc, link } = req.body;
  await db.read();
  const idx = db.data.products.findIndex(p => p.id === id);
  if(idx === -1) return res.status(404).json({ error: 'No encontrado' });
  const p = db.data.products[idx];
  db.data.products[idx] = {
    ...p,
    title: title ?? p.title,
    image: image ?? p.image,
    price: price ?? p.price,
    tag: tag ?? p.tag,
    desc: desc ?? p.desc,
    link: link ?? p.link
  };
  await db.write();
  res.json({ ok: true, product: db.data.products[idx] });
});

app.delete('/api/products/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  await db.read();
  const before = db.data.products.length;
  db.data.products = db.data.products.filter(p => p.id !== id);
  if (db.data.products.length === before) return res.status(404).json({ error: 'No encontrado' });
  await db.write();
  res.json({ ok: true });
});

// ---- Subida de imagen (admin)
app.post('/api/upload', requireAdmin, upload.single('image'), (req, res) => {
  const publicUrl = `/uploads/${req.file.filename}`;
  res.json({ ok: true, url: publicUrl });
});

// ---- Variables públicas para el cliente
app.get('/api/public-config', (req, res) => {
  res.json({
    discordInvite: process.env.PUBLIC_DISCORD_INVITE,
    discordUser: process.env.PUBLIC_DISCORD_USER
  });
});

// ---- Arrancar
app.listen(PORT, () => {
  console.log(`okuSystem corriendo en http://localhost:${PORT}`);
});
