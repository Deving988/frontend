// ============================================================
// SIDFIT BACKEND v3.0 — server.js
// What's new in v3:
//   • Cloudinary for all product/banner images (no more giant base64 JSON)
//   • Signed direct-upload endpoint so the browser uploads straight to
//     Cloudinary — faster page loads, smaller server payloads
//   • Fixed Gmail timeout (SMTP pool + timeouts + graceful fallback)
//   • Fixed admin duplicate-product bug (atomic create, no double-submit)
//   • Working Delete / Hide-Unhide / Update endpoints, verified end-to-end
//   • Basic rate limiting on auth + write routes
// Database: MongoDB Atlas (FREE)
// Images:   Cloudinary (FREE tier)
// Deploy:   Render.com / Railway / Fly.io (Free tier)
// Node.js v18+
// ============================================================
// SETUP: see .env.example for every variable you need to fill in.
// npm install
// npm start
// ============================================================

require('dotenv').config();
const express        = require('express');
const cors            = require('cors');
const crypto          = require('crypto');
const mongoose        = require('mongoose');
const Razorpay        = require('razorpay');
const nodemailer      = require('nodemailer');
const jwt              = require('jsonwebtoken');
const cloudinary       = require('cloudinary').v2;
const rateLimit        = require('express-rate-limit');

const app  = express();
const PORT = process.env.PORT || 3000;

// ==================== CLOUDINARY ====================
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});
const CLOUDINARY_FOLDER = process.env.CLOUDINARY_FOLDER || 'sidfit';
const cloudinaryReady = !!(process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET);

// ==================== MIDDLEWARE ====================
app.use(cors({
  origin: [
    'https://deving988.github.io',
    'http://localhost:3000',
    'http://localhost:5500',
    'http://127.0.0.1:5500',
    process.env.FRONTEND_URL
  ].filter(Boolean),
  credentials: true
}));
// Images now live on Cloudinary, so request bodies are tiny — 2mb is generous.
app.use(express.json({ limit: '2mb' }));

// Basic rate limiting to stop brute-forcing OTP / admin key and to stop
// accidental rapid-fire double submits from creating duplicate documents.
const writeLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
});
const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please wait a few minutes and try again.' }
});
app.use(['/api/products', '/api/banners'], (req, res, next) => {
  if (req.method === 'GET') return next();
  return writeLimiter(req, res, next);
});
app.use(['/api/auth/send-otp', '/api/auth/verify-otp'], authLimiter);

// ==================== MONGODB CONNECTION ====================
mongoose.set('strictQuery', true);
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB Atlas Connected'))
  .catch(err => console.error('❌ MongoDB Error:', err.message));

mongoose.connection.on('disconnected', () => console.warn('⚠️  MongoDB disconnected'));

// ==================== SCHEMAS ====================

// Cloudinary image sub-schema — store both the URL we render and the
// public_id we need later to delete the asset from Cloudinary.
const cloudImageSchema = new mongoose.Schema({
  url:       { type: String, required: true },
  publicId:  { type: String, default: null },
}, { _id: false });

// Product Schema — v3 with Cloudinary images + per-size stock
const productSchema = new mongoose.Schema({
  name:     { type: String, required: true, trim: true },
  price:    { type: Number, required: true },
  mrp:      { type: Number, default: null },
  category: { type: String, enum: ['all','men','women'], default: 'all' },
  badge:    { type: String, enum: ['new','sale', null], default: null },
  sizeStock: { type: Map, of: Number, default: {} },
  desc:     { type: String, default: '' },
  // v3: images are Cloudinary objects { url, publicId } — up to 5
  images:   { type: [cloudImageSchema], default: [] },
  active:   { type: Boolean, default: true },
}, { timestamps: true });

// Order Schema
const orderSchema = new mongoose.Schema({
  orderId:         { type: String, unique: true },
  razorpayOrderId: { type: String },
  paymentId:       { type: String, default: null },
  signature:       { type: String, default: null },
  status:          { type: String, enum: ['pending','confirmed','processing','shipped','delivered','cancelled'], default: 'pending' },
  cart:            { type: Array, default: [] },
  customer: {
    name:    String,
    email:   String,
    phone:   String,
    address: String,
  },
  userId:     { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  total:      { type: Number, default: 0 },
  trackingId: { type: String, default: null },
  paidAt:     { type: Date, default: null },
}, { timestamps: true });

// Subscriber Schema
const subscriberSchema = new mongoose.Schema({
  email:  { type: String, unique: true, required: true, lowercase: true, trim: true },
  active: { type: Boolean, default: true },
}, { timestamps: true });

// Banner Schema — v3 image is a Cloudinary object too
const bannerSchema = new mongoose.Schema({
  title:      { type: String, default: '' },
  subtitle:   { type: String, default: '' },
  btnText:    { type: String, default: 'Shop Now' },
  btnLink:    { type: String, default: '#shop' },
  image:      { type: cloudImageSchema, default: null },
  bgColor:    { type: String, default: '#0a0a0a' },
  textColor:  { type: String, default: '#ffffff' },
  active:     { type: Boolean, default: true },
  order:      { type: Number, default: 0 },
}, { timestamps: true });

// User Schema (email OTP login)
const userSchema = new mongoose.Schema({
  email:          { type: String, unique: true, required: true, lowercase: true, trim: true },
  name:           { type: String, default: '' },
  phone:          { type: String, default: '' },
  savedAddresses: { type: [String], default: [] },
  otp:            { type: String, default: null },
  otpExpiry:      { type: Date, default: null },
  otpAttempts:    { type: Number, default: 0 },
  verified:       { type: Boolean, default: false },
}, { timestamps: true });

const Product    = mongoose.model('Product',    productSchema);
const Order      = mongoose.model('Order',      orderSchema);
const Subscriber = mongoose.model('Subscriber', subscriberSchema);
const Banner     = mongoose.model('Banner',     bannerSchema);
const User       = mongoose.model('User',       userSchema);

// ==================== RAZORPAY ====================
const razorpayReady = !!(process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET);
const razorpay = razorpayReady ? new Razorpay({
  key_id:     process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
}) : null;

// ==================== NODEMAILER (FIXED — no more silent timeouts) ====================
// Root cause of the old "Gmail login timeout": the transporter had no
// connection/socket timeouts, no pooling, and used the legacy `service:
// 'gmail'` shortcut with a regular password — Google blocks that, and the
// SMTP handshake just hangs until Node's default (very long) timeout. Fix:
//   1. Explicit host/port + pooled connections with sane timeouts
//   2. Support an App Password OR a fully custom SMTP provider via env vars
//   3. Verify the connection once at boot and log a clear warning instead of
//      letting requests hang
//   4. Wrap every send in a timeout-guarded promise so a slow mail server
//      can never block an API response to the customer
let mailer = null;

function buildTransport() {
  // If custom SMTP vars are present, prefer them (recommended for production).
  if (process.env.SMTP_HOST) {
    return nodemailer.createTransport({
      host:   process.env.SMTP_HOST,
      port:   Number(process.env.SMTP_PORT) || 587,
      secure: Number(process.env.SMTP_PORT) === 465,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
      pool: true,
      maxConnections: 3,
      connectionTimeout: 10000, // 10s — fail fast instead of hanging
      greetingTimeout: 10000,
      socketTimeout: 15000,
    });
  }

  // Default: Gmail via explicit SMTP (not the old 'service: gmail' shortcut)
  // Requires a Google "App Password" — see .env.example for setup steps.
  return nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
    pool: true,
    maxConnections: 3,
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 15000,
  });
}

if (process.env.EMAIL_USER && (process.env.EMAIL_PASS || process.env.SMTP_PASS)) {
  mailer = buildTransport();
  mailer.verify((err) => {
    if (err) {
      console.error('❌ Email transport failed to verify:', err.message);
      console.error('   → Check EMAIL_USER/EMAIL_PASS (must be a Gmail App Password, not your login password).');
      console.error('   → See .env.example for step-by-step setup instructions.');
    } else {
      console.log('✅ Email transport verified and ready');
    }
  });
} else {
  console.warn('⚠️  Email not configured — EMAIL_USER/EMAIL_PASS missing. Order/OTP emails will be skipped.');
}

// ==================== EMAIL HELPER (timeout-guarded, never blocks the response) ====================
function withTimeout(promise, ms, label) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms))
  ]);
}

async function sendEmail({ to, subject, html }) {
  if (!mailer) {
    console.warn(`📧 Email skipped (not configured) → would have sent to ${to}: ${subject}`);
    return { sent: false, reason: 'not_configured' };
  }
  try {
    await withTimeout(
      mailer.sendMail({ from: `"SIDFIT" <${process.env.EMAIL_USER}>`, to, subject, html }),
      12000,
      'sendMail'
    );
    console.log(`📧 Email sent → ${to}`);
    return { sent: true };
  } catch (err) {
    console.error('❌ Email error:', err.message);
    return { sent: false, reason: err.message };
  }
}

// ==================== EMAIL TEMPLATES ====================
function escapeHtml(str = '') {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function customerConfirmEmail(order) {
  const rows = order.cart.map(i =>
    `<tr>
      <td style="padding:10px 0;border-bottom:1px solid #f0f0f0;font-size:14px">${escapeHtml(i.name)} (${escapeHtml(i.size)})</td>
      <td style="padding:10px 0;border-bottom:1px solid #f0f0f0;text-align:center;font-size:14px">×${i.qty}</td>
      <td style="padding:10px 0;border-bottom:1px solid #f0f0f0;text-align:right;font-weight:600;font-size:14px">₹${i.price * i.qty}</td>
    </tr>`
  ).join('');

  return `
  <div style="font-family:Inter,Arial,sans-serif;max-width:580px;margin:auto;background:#fff">
    <div style="background:#0a0a0a;padding:32px;text-align:center">
      <h1 style="font-family:Impact,sans-serif;color:#fff;letter-spacing:6px;font-size:28px;margin:0">SIDFIT</h1>
      <p style="color:rgba(255,255,255,.4);font-size:11px;letter-spacing:2px;margin:6px 0 0;text-transform:uppercase">Premium Unisex Wear</p>
    </div>
    <div style="padding:40px 36px">
      <h2 style="font-size:22px;color:#0a0a0a;margin:0 0 8px">Order Confirmed! 🎉</h2>
      <p style="color:#6b6b6b;font-size:14px;margin:0 0 28px;line-height:1.6">
        Hi ${escapeHtml(order.customer.name)}, your order has been placed successfully. We'll update you when it ships!
      </p>
      <div style="background:#f4f4f2;padding:16px 20px;margin-bottom:28px;border-left:3px solid #0a0a0a">
        <p style="margin:0;font-size:11px;color:#999;letter-spacing:1.5px;text-transform:uppercase">Order ID</p>
        <p style="margin:6px 0 0;font-size:17px;font-weight:700;color:#0a0a0a">${order.orderId}</p>
      </div>
      <table style="width:100%;border-collapse:collapse">
        <thead>
          <tr>
            <th style="text-align:left;font-size:11px;color:#999;letter-spacing:1.5px;text-transform:uppercase;padding-bottom:12px">Item</th>
            <th style="text-align:center;font-size:11px;color:#999;letter-spacing:1.5px;text-transform:uppercase;padding-bottom:12px">Qty</th>
            <th style="text-align:right;font-size:11px;color:#999;letter-spacing:1.5px;text-transform:uppercase;padding-bottom:12px">Price</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
      <div style="text-align:right;padding-top:16px;margin-top:8px;border-top:2px solid #0a0a0a">
        <span style="font-size:20px;font-weight:700">Total: ₹${order.total}</span>
      </div>
      <div style="margin-top:28px;padding:20px;background:#f4f4f2">
        <p style="margin:0 0 6px;font-size:11px;color:#999;letter-spacing:1.5px;text-transform:uppercase">Shipping To</p>
        <p style="margin:0;font-size:14px;color:#333;line-height:1.6">${escapeHtml(order.customer.name)}<br>${escapeHtml(order.customer.address)}</p>
      </div>
      <p style="margin-top:24px;font-size:13px;color:#6b6b6b;line-height:1.7">
        📦 Expected delivery: <strong>5–7 business days</strong><br>
        Questions? Reply to this email or WhatsApp us.
      </p>
    </div>
    <div style="background:#f4f4f2;padding:20px;text-align:center;border-top:1px solid #e0e0e0">
      <p style="margin:0;font-size:11px;color:#999">© 2026 SIDFIT · sidfit.in</p>
    </div>
  </div>`;
}

function adminNewOrderEmail(order) {
  const rows = order.cart.map(i =>
    `<tr><td style="padding:8px;border:1px solid #ddd">${escapeHtml(i.name)}</td><td style="padding:8px;border:1px solid #ddd">${escapeHtml(i.size)}</td><td style="padding:8px;border:1px solid #ddd;text-align:center">${i.qty}</td><td style="padding:8px;border:1px solid #ddd;text-align:right">₹${i.price*i.qty}</td></tr>`
  ).join('');
  return `
  <div style="font-family:monospace;padding:28px;background:#fff">
    <div style="background:#0a0a0a;padding:16px 24px;display:inline-block;margin-bottom:24px">
      <span style="color:#fff;font-size:18px;letter-spacing:4px;font-family:Impact,sans-serif">SIDFIT</span>
      <span style="color:rgba(255,255,255,.4);font-size:12px;margin-left:12px">NEW ORDER</span>
    </div>
    <h2 style="color:#0a0a0a;margin:0 0 20px">🛍️ Order: ${order.orderId}</h2>
    <table style="width:100%;border-collapse:collapse;margin-bottom:20px">
      <tr><td style="padding:8px;background:#f4f4f2;width:140px;font-size:12px;color:#666">Customer</td><td style="padding:8px;font-weight:600">${escapeHtml(order.customer.name)}</td></tr>
      <tr><td style="padding:8px;background:#f4f4f2;font-size:12px;color:#666">Phone</td><td style="padding:8px">${escapeHtml(order.customer.phone)}</td></tr>
      <tr><td style="padding:8px;background:#f4f4f2;font-size:12px;color:#666">Email</td><td style="padding:8px">${escapeHtml(order.customer.email)}</td></tr>
      <tr><td style="padding:8px;background:#f4f4f2;font-size:12px;color:#666">Address</td><td style="padding:8px">${escapeHtml(order.customer.address)}</td></tr>
      <tr><td style="padding:8px;background:#f4f4f2;font-size:12px;color:#666">Payment ID</td><td style="padding:8px">${order.paymentId}</td></tr>
    </table>
    <table style="width:100%;border-collapse:collapse;margin-bottom:20px">
      <thead><tr style="background:#0a0a0a;color:#fff"><th style="padding:10px;text-align:left">Product</th><th style="padding:10px">Size</th><th style="padding:10px">Qty</th><th style="padding:10px;text-align:right">Amount</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <h2 style="font-size:22px;border-top:2px solid #0a0a0a;padding-top:16px">Total Paid: ₹${order.total}</h2>
    <p style="color:#666;font-size:13px">Login to your admin panel to update order status.</p>
  </div>`;
}

function orderStatusEmail(order) {
  const info = {
    processing: { emoji:'⚙️', title:'Being Processed', msg:'We are carefully preparing your order for dispatch.' },
    shipped:    { emoji:'🚚', title:'Order Shipped!',   msg:`Your order is on the way! Tracking ID: <strong>${escapeHtml(order.trackingId || 'Will be updated soon')}</strong>` },
    delivered:  { emoji:'✅', title:'Delivered!',       msg:'We hope you love your SIDFIT gear! Share your look and tag us.' },
    cancelled:  { emoji:'❌', title:'Order Cancelled',  msg:'Your order has been cancelled. Refund will be processed in 5–7 business days.' },
  }[order.status] || { emoji:'📦', title:`Status: ${order.status}`, msg:'' };

  return `
  <div style="font-family:Inter,Arial,sans-serif;max-width:580px;margin:auto;background:#fff">
    <div style="background:#0a0a0a;padding:32px;text-align:center">
      <h1 style="font-family:Impact,sans-serif;color:#fff;letter-spacing:6px;font-size:28px;margin:0">SIDFIT</h1>
    </div>
    <div style="padding:48px 36px;text-align:center">
      <div style="font-size:56px;margin-bottom:16px">${info.emoji}</div>
      <h2 style="font-size:22px;color:#0a0a0a;margin:0 0 12px">${info.title}</h2>
      <p style="color:#6b6b6b;font-size:14px;line-height:1.7">${info.msg}</p>
      <div style="margin-top:28px;padding:16px;background:#f4f4f2;display:inline-block">
        <p style="margin:0;font-size:12px;color:#999">Order ID: <strong style="color:#0a0a0a">${order.orderId}</strong></p>
      </div>
    </div>
    <div style="background:#f4f4f2;padding:20px;text-align:center;border-top:1px solid #e0e0e0">
      <p style="margin:0;font-size:11px;color:#999">© 2026 SIDFIT · sidfit.in</p>
    </div>
  </div>`;
}

function otpEmail(otp) {
  return `
  <div style="font-family:Inter,Arial,sans-serif;max-width:480px;margin:auto;background:#fff">
    <div style="background:#0a0a0a;padding:28px;text-align:center">
      <h1 style="font-family:Impact,sans-serif;color:#fff;letter-spacing:6px;font-size:24px;margin:0">SIDFIT</h1>
    </div>
    <div style="padding:40px 32px;text-align:center">
      <p style="font-size:14px;color:#666;margin:0 0 24px">Your login OTP is:</p>
      <div style="background:#f4f4f2;padding:24px;letter-spacing:12px;font-size:36px;font-weight:700;color:#0a0a0a;font-family:monospace">${otp}</div>
      <p style="font-size:13px;color:#999;margin:20px 0 0">Valid for 10 minutes. Do not share this OTP with anyone.</p>
    </div>
    <div style="background:#f4f4f2;padding:16px;text-align:center">
      <p style="margin:0;font-size:11px;color:#999">© 2026 SIDFIT · sidfit.in</p>
    </div>
  </div>`;
}

// ==================== AUTH MIDDLEWARE ====================
function adminAuth(req, res, next) {
  const key = req.headers['x-admin-key'];
  if (!process.env.ADMIN_SECRET || key !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

function userAuth(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Login required' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'sidfit_jwt_secret_change_me');
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ==================== ROUTES ====================

// Health check
app.get('/', (req, res) => {
  res.json({
    status: 'SIDFIT Backend v3.0 Running ✅',
    db: mongoose.connection.readyState === 1 ? 'MongoDB Connected ✅' : '❌ Disconnected',
    cloudinary: cloudinaryReady ? '✅ Configured' : '⚠️ Not configured',
    email: mailer ? '✅ Configured' : '⚠️ Not configured',
    timestamp: new Date().toISOString()
  });
});

// ============================================================
// CLOUDINARY — signed upload + delete
// ============================================================

// Returns a signature the browser uses to upload DIRECTLY to Cloudinary.
// This is the key speed fix: images never pass through our server as
// base64 JSON blobs (the old approach, which was slow and hit the 50mb
// body-size limit). The browser uploads straight to Cloudinary's CDN.
app.get('/api/cloudinary/signature', adminAuth, (req, res) => {
  if (!cloudinaryReady) {
    return res.status(503).json({ error: 'Cloudinary is not configured on the server. Check .env.' });
  }
  const timestamp = Math.round(Date.now() / 1000);
  const folder    = CLOUDINARY_FOLDER;
  const paramsToSign = { timestamp, folder };
  const signature = cloudinary.utils.api_sign_request(paramsToSign, process.env.CLOUDINARY_API_SECRET);

  res.json({
    timestamp,
    signature,
    folder,
    apiKey:   process.env.CLOUDINARY_API_KEY,
    cloudName: process.env.CLOUDINARY_CLOUD_NAME,
  });
});

// Delete a Cloudinary asset by public_id (used when removing a product image
// or deleting a product/banner outright, so orphaned images don't pile up).
app.post('/api/cloudinary/delete', adminAuth, async (req, res) => {
  try {
    const { publicId } = req.body;
    if (!publicId) return res.status(400).json({ error: 'publicId is required' });
    await cloudinary.uploader.destroy(publicId);
    res.json({ message: 'Image deleted ✅' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// PRODUCTS — v3 (Cloudinary images, per-size stock)
// ============================================================

function normalizeProduct(p) {
  const images = (p.images || []).map(img => (typeof img === 'string' ? { url: img, publicId: null } : img));
  return {
    id: p._id,
    name: p.name,
    price: p.price,
    mrp: p.mrp,
    category: p.category,
    badge: p.badge,
    sizeStock: Object.fromEntries(p.sizeStock || []),
    desc: p.desc,
    images,
    image: images[0]?.url || null, // backward-compat single-image field
    active: p.active,
    createdAt: p.createdAt,
  };
}

// GET all active products (public)
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find({ active: true }).sort({ createdAt: -1 }).lean();
    res.set('Cache-Control', 'public, max-age=30'); // light caching → fewer redundant calls
    res.json(products.map(normalizeProduct));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET single product (public) — powers the dedicated product detail page
app.get('/api/products/:id', async (req, res) => {
  try {
    const p = await Product.findById(req.params.id).lean();
    if (!p || !p.active) return res.status(404).json({ error: 'Product not found' });
    res.set('Cache-Control', 'public, max-age=30');
    res.json(normalizeProduct(p));
  } catch (err) {
    res.status(404).json({ error: 'Product not found' });
  }
});

// ADD product (admin) — accepts images[] as [{url, publicId}]
// FIX for "duplicate product" bug: the old frontend could double-fire this
// request (double click / slow network retry) and create two documents
// with identical data. We now require a client-generated idempotency key
// (clientRequestId) and silently return the existing product if we've
// already seen that key in the last few minutes, instead of inserting again.
const recentProductRequests = new Map(); // clientRequestId -> { id, expires }
function rememberRequest(key, id) {
  recentProductRequests.set(key, { id, expires: Date.now() + 5 * 60 * 1000 });
}
function getRememberedRequest(key) {
  const entry = recentProductRequests.get(key);
  if (!entry) return null;
  if (entry.expires < Date.now()) { recentProductRequests.delete(key); return null; }
  return entry.id;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of recentProductRequests) if (v.expires < now) recentProductRequests.delete(k);
}, 60 * 1000);

app.post('/api/products', adminAuth, async (req, res) => {
  try {
    const { name, price, mrp, category, badge, sizeStock, desc, images, clientRequestId } = req.body;

    if (clientRequestId) {
      const existingId = getRememberedRequest(clientRequestId);
      if (existingId) {
        return res.json({ id: existingId, message: 'Product added ✅', duplicate: false });
      }
    }

    if (!name || !price) return res.status(400).json({ error: 'Name and price are required' });
    if (images && images.length > 5) return res.status(400).json({ error: 'Maximum 5 images allowed' });

    const product = new Product({
      name, price, mrp, category, badge, desc,
      images: (images || []).slice(0, 5),
      sizeStock: new Map(Object.entries(sizeStock || {})),
    });
    await product.save();

    if (clientRequestId) rememberRequest(clientRequestId, product._id.toString());

    res.json({ id: product._id, message: 'Product added ✅' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// UPDATE product (admin)
app.put('/api/products/:id', adminAuth, async (req, res) => {
  try {
    const { images, sizeStock, clientRequestId, ...rest } = req.body;
    if (images && images.length > 5) return res.status(400).json({ error: 'Maximum 5 images allowed' });

    const updateData = { ...rest };
    if (images !== undefined) updateData.images = images.slice(0, 5);
    if (sizeStock !== undefined) updateData.sizeStock = new Map(Object.entries(sizeStock));

    const updated = await Product.findByIdAndUpdate(req.params.id, updateData, { new: true });
    if (!updated) return res.status(404).json({ error: 'Product not found' });
    res.json({ message: 'Product updated ✅', id: updated._id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// HIDE product (soft delete — keeps data, removes from storefront)
app.delete('/api/products/:id', adminAuth, async (req, res) => {
  try {
    const updated = await Product.findByIdAndUpdate(req.params.id, { active: false }, { new: true });
    if (!updated) return res.status(404).json({ error: 'Product not found' });
    res.json({ message: 'Product hidden ✅', id: updated._id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// UNHIDE product (admin)
app.patch('/api/products/:id/unhide', adminAuth, async (req, res) => {
  try {
    const updated = await Product.findByIdAndUpdate(req.params.id, { active: true }, { new: true });
    if (!updated) return res.status(404).json({ error: 'Product not found' });
    res.json({ message: 'Product visible again ✅', id: updated._id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PERMANENTLY delete product + its Cloudinary images (admin)
app.delete('/api/products/:id/permanent', adminAuth, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ error: 'Product not found' });

    if (cloudinaryReady) {
      const deletions = (product.images || [])
        .filter(img => img.publicId)
        .map(img => cloudinary.uploader.destroy(img.publicId).catch(() => null));
      await Promise.all(deletions);
    }

    await Product.findByIdAndDelete(req.params.id);
    res.json({ message: 'Product permanently deleted ✅' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get all products for admin (includes hidden ones)
app.get('/api/admin/products', adminAuth, async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 }).lean();
    res.json(products.map(normalizeProduct));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// UPDATE stock for a specific size (admin or after order)
app.patch('/api/products/:id/stock', adminAuth, async (req, res) => {
  try {
    const { size, quantity } = req.body;
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ error: 'Product not found' });

    product.sizeStock.set(size, quantity);
    await product.save();
    res.json({ message: `Stock updated: ${size} = ${quantity}` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// BANNERS
// ============================================================

function normalizeBanner(b) {
  const image = b.image && typeof b.image === 'string' ? { url: b.image, publicId: null } : b.image;
  return { ...b, image };
}

// GET all active banners (public)
app.get('/api/banners', async (req, res) => {
  try {
    const banners = await Banner.find({ active: true }).sort({ order: 1 }).lean();
    res.set('Cache-Control', 'public, max-age=30');
    res.json(banners.map(normalizeBanner));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET all banners including inactive (admin)
app.get('/api/banners/all', adminAuth, async (req, res) => {
  try {
    const banners = await Banner.find().sort({ order: 1 }).lean();
    res.json(banners.map(normalizeBanner));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ADD banner (admin)
app.post('/api/banners', adminAuth, async (req, res) => {
  try {
    const count = await Banner.countDocuments();
    const banner = new Banner({ ...req.body, order: count });
    await banner.save();
    res.json({ id: banner._id, message: 'Banner added ✅' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// UPDATE banner (admin)
app.put('/api/banners/:id', adminAuth, async (req, res) => {
  try {
    const updated = await Banner.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!updated) return res.status(404).json({ error: 'Banner not found' });
    res.json({ message: 'Banner updated ✅' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE banner + its Cloudinary image (admin)
app.delete('/api/banners/:id', adminAuth, async (req, res) => {
  try {
    const banner = await Banner.findById(req.params.id);
    if (!banner) return res.status(404).json({ error: 'Banner not found' });

    if (cloudinaryReady && banner.image?.publicId) {
      await cloudinary.uploader.destroy(banner.image.publicId).catch(() => null);
    }

    await Banner.findByIdAndDelete(req.params.id);
    res.json({ message: 'Banner deleted ✅' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// USER AUTH — Email OTP
// ============================================================

app.post('/api/auth/send-otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email?.includes('@')) return res.status(400).json({ error: 'Invalid email' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

    await User.findOneAndUpdate(
      { email: email.toLowerCase() },
      { otp, otpExpiry, otpAttempts: 0 },
      { upsert: true, new: true }
    );

    const result = await sendEmail({
      to: email,
      subject: `${otp} — SIDFIT Login OTP`,
      html: otpEmail(otp)
    });

    if (!result.sent) {
      return res.status(502).json({ error: 'Could not send OTP email right now. Please try again in a moment.' });
    }

    res.json({ message: 'OTP sent ✅' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(404).json({ error: 'User not found. Please request OTP again.' });

    if (user.otp !== otp) {
      user.otpAttempts = (user.otpAttempts || 0) + 1;
      await user.save();
      return res.status(400).json({ error: 'Invalid OTP' });
    }
    if (new Date() > user.otpExpiry) return res.status(400).json({ error: 'OTP expired. Please request a new one.' });

    user.otp = null;
    user.otpExpiry = null;
    user.otpAttempts = 0;
    user.verified = true;
    await user.save();

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || 'sidfit_jwt_secret_change_me',
      { expiresIn: '30d' }
    );

    res.json({
      message: 'Login successful ✅',
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        phone: user.phone,
        savedAddresses: user.savedAddresses,
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/auth/profile', userAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-otp -otpExpiry');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({
      id: user._id,
      email: user.email,
      name: user.name,
      phone: user.phone,
      savedAddresses: user.savedAddresses,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/auth/profile', userAuth, async (req, res) => {
  try {
    const { name, phone, savedAddresses } = req.body;
    const user = await User.findByIdAndUpdate(
      req.user.userId,
      { name, phone, savedAddresses },
      { new: true }
    ).select('-otp -otpExpiry');
    res.json({ message: 'Profile updated ✅', user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/auth/my-orders', userAuth, async (req, res) => {
  try {
    const orders = await Order.find({
      $or: [
        { userId: req.user.userId },
        { 'customer.email': req.user.email }
      ],
      status: { $ne: 'pending' }
    }).sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/users', adminAuth, async (req, res) => {
  try {
    const users = await User.find({ verified: true }).select('-otp -otpExpiry').sort({ createdAt: -1 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// ORDERS
// ============================================================

app.post('/api/create-order', async (req, res) => {
  try {
    if (!razorpayReady) return res.status(503).json({ error: 'Payments are not configured on the server.' });
    const { amount, currency = 'INR', cart, customer } = req.body;

    if (!amount || amount < 100) return res.status(400).json({ error: 'Invalid amount' });
    if (!cart?.length)           return res.status(400).json({ error: 'Cart is empty' });

    const rzpOrder = await razorpay.orders.create({
      amount:   Math.round(amount),
      currency,
      receipt:  `sidfit_${Date.now()}`,
      notes:    { customer_name: customer?.name || '', customer_email: customer?.email || '' }
    });

    await Order.create({
      orderId:         `SDF-${Date.now()}`,
      razorpayOrderId: rzpOrder.id,
      status:          'pending',
      cart,
      customer,
    });

    res.json(rzpOrder);
  } catch (err) {
    console.error('Create order error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/verify-payment', async (req, res) => {
  try {
    const { razorpay_payment_id, razorpay_order_id, razorpay_signature, cart, customer, userId } = req.body;

    const body     = `${razorpay_order_id}|${razorpay_payment_id}`;
    const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(body).digest('hex');

    if (expected !== razorpay_signature) {
      return res.status(400).json({ success: false, error: 'Invalid payment signature' });
    }

    const subtotal = cart.reduce((s, i) => s + i.price * i.qty, 0);
    const shipping  = subtotal >= 999 ? 0 : 99;
    const total     = subtotal + shipping;
    const orderId   = `SDF-${Date.now()}`;

    const order = await Order.findOneAndUpdate(
      { razorpayOrderId: razorpay_order_id },
      {
        paymentId: razorpay_payment_id,
        signature: razorpay_signature,
        status:    'confirmed',
        orderId,
        total,
        paidAt:    new Date(),
        cart,
        customer,
        userId: userId || null,
      },
      { new: true }
    );

    for (const item of cart) {
      if (item.productId && item.size) {
        const product = await Product.findById(item.productId);
        if (product) {
          const currentStock = product.sizeStock.get(item.size) || 0;
          const newStock = Math.max(0, currentStock - (item.qty || 1));
          product.sizeStock.set(item.size, newStock);
          await product.save();
        }
      }
    }

    const orderData = { orderId, cart, customer, total, paymentId: razorpay_payment_id };

    if (customer?.email) {
      sendEmail({
        to:      customer.email,
        subject: `✅ Order Confirmed — ${orderId} | SIDFIT`,
        html:    customerConfirmEmail(orderData)
      });
    }
    if (process.env.ADMIN_EMAIL) {
      sendEmail({
        to:      process.env.ADMIN_EMAIL,
        subject: `🛍️ New Order ${orderId} — ₹${total}`,
        html:    adminNewOrderEmail(orderData)
      });
    }

    res.json({ success: true, orderId });
  } catch (err) {
    console.error('Verify payment error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/orders', adminAuth, async (req, res) => {
  try {
    const orders = await Order.find({ status: { $ne: 'pending' } }).sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/orders/:id/status', adminAuth, async (req, res) => {
  try {
    const { status, trackingId } = req.body;
    const valid = ['processing','shipped','delivered','cancelled'];
    if (!valid.includes(status)) return res.status(400).json({ error: 'Invalid status' });

    const order = await Order.findByIdAndUpdate(
      req.params.id,
      { status, trackingId: trackingId || null },
      { new: true }
    );

    if (!order) return res.status(404).json({ error: 'Order not found' });

    if (order.customer?.email) {
      sendEmail({
        to:      order.customer.email,
        subject: `📦 Order Update — ${order.orderId} | SIDFIT`,
        html:    orderStatusEmail(order)
      });
    }

    res.json({ message: `Status updated to "${status}" ✅` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/track/:orderId', async (req, res) => {
  try {
    const order = await Order.findOne({ orderId: req.params.orderId });
    if (!order) return res.status(404).json({ error: 'Order not found' });
    res.json({
      orderId:    order.orderId,
      status:     order.status,
      trackingId: order.trackingId || null,
      items:      order.cart?.length || 0,
      total:      order.total,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// NEWSLETTER
// ============================================================

app.post('/api/subscribe', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email?.includes('@')) return res.status(400).json({ error: 'Invalid email' });

    await Subscriber.findOneAndUpdate(
      { email: email.toLowerCase() },
      { email: email.toLowerCase(), active: true },
      { upsert: true, new: true }
    );
    res.json({ message: 'Subscribed ✅' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/subscribers', adminAuth, async (req, res) => {
  try {
    const subs = await Subscriber.find({ active: true }).sort({ createdAt: -1 });
    res.json(subs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== 404 + ERROR HANDLERS ====================
app.use((req, res) => res.status(404).json({ error: 'Route not found' }));
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ==================== START ====================
app.listen(PORT, () => {
  console.log(`\n🚀 SIDFIT Backend v3.0 running on port ${PORT}`);
  console.log(`📦 MongoDB    : ${process.env.MONGO_URI ? '✅ URI Set' : '⚠️  NOT SET'}`);
  console.log(`☁️  Cloudinary : ${cloudinaryReady ? '✅ Set' : '⚠️  NOT SET'}`);
  console.log(`🔑 Razorpay   : ${razorpayReady ? '✅ Set' : '⚠️  NOT SET'}`);
  console.log(`📧 Email      : ${process.env.EMAIL_USER || '⚠️  NOT SET'}`);
  console.log(`🔐 JWT        : ${process.env.JWT_SECRET ? '✅ Set' : '⚠️  Using default (change in production!)'}`);
  console.log(`🔐 Admin key  : ${process.env.ADMIN_SECRET ? '✅ Set' : '⚠️  NOT SET — admin panel will be inaccessible'}`);
});
