// ══════════════════════════════════════
// MiCaja Backend — server.js v2.2
// FIX: sistema de sesiones WhatsApp
// Cambios vs v2.1:
//   - setCtx ya NO hace merge con ctx viejo (era el bug principal)
//   - clearCtx usa setCtxByPhone para consistencia
//   - flujo menu usa setCtxByPhone directamente
//   - processWhatsAppMessage relee ctx fresco después de clearCtx
// ══════════════════════════════════════

const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const WA_TOKEN = process.env.WA_TOKEN;
const WA_VERIFY_TOKEN = process.env.WA_VERIFY_TOKEN || 'micaja_verify_2026';
const WA_PHONE_ID = process.env.WA_PHONE_ID;
const BOLD_API_KEY = process.env.BOLD_API_KEY;
const BOLD_SECRET_KEY = process.env.BOLD_SECRET_KEY;

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// ══════════════════════════════════════
// RATE LIMITING
// ══════════════════════════════════════
const rateLimitStore = new Map();

function rateLimit(maxPerMinute, maxPerHour) {
  return (req, res, next) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.ip || 'unknown';
    const phone = req.body?.phone || req.params?.phone || '';
    const key = phone ? `${ip}:${phone}` : ip;
    const now = Date.now();

    if (rateLimitStore.size > 1000) {
      for (const [k, v] of rateLimitStore) {
        if (v.hourResetAt < now) rateLimitStore.delete(k);
      }
    }

    const entry = rateLimitStore.get(key) || {
      minCount: 0, minResetAt: now + 60000,
      hourCount: 0, hourResetAt: now + 3600000
    };

    if (entry.minResetAt < now) { entry.minCount = 0; entry.minResetAt = now + 60000; }
    if (entry.hourResetAt < now) { entry.hourCount = 0; entry.hourResetAt = now + 3600000; }

    entry.minCount++;
    entry.hourCount++;
    rateLimitStore.set(key, entry);

    if (entry.minCount > maxPerMinute) {
      console.warn(`⚠️ Rate limit (min) alcanzado: ${key}`);
      return res.status(429).json({ error: 'Demasiadas peticiones. Espera un momento.' });
    }
    if (entry.hourCount > maxPerHour) {
      console.warn(`⚠️ Rate limit (hora) alcanzado: ${key}`);
      return res.status(429).json({ error: 'Límite de peticiones alcanzado. Intenta en una hora.' });
    }
    next();
  };
}

const waMessageStore = new Map();

function rateLimitWA(phone, maxPerDay = 150, maxPerMinute = 15) {
  const now = Date.now();
  const entry = waMessageStore.get(phone) || {
    dayCount: 0, dayResetAt: now + 86400000,
    minCount: 0, minResetAt: now + 60000
  };
  if (entry.dayResetAt < now) { entry.dayCount = 0; entry.dayResetAt = now + 86400000; }
  if (entry.minResetAt < now) { entry.minCount = 0; entry.minResetAt = now + 60000; }
  entry.dayCount++;
  entry.minCount++;
  waMessageStore.set(phone, entry);
  if (entry.minCount > maxPerMinute) return { blocked: true, reason: 'minuto' };
  if (entry.dayCount > maxPerDay) return { blocked: true, reason: 'dia' };
  return { blocked: false };
}

// ══════ HEALTH CHECK ══════
app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'MiCaja Backend', version: '2.2.0', timestamp: new Date().toISOString() });
});

function normalizePhone(phone) {
  let p = phone.replace(/[\s\-\+\(\)]/g, '');
  if (p.startsWith('57') && p.length === 12) return p;
  if (p.length === 10 && p.startsWith('3')) return '57' + p;
  if (p.startsWith('0057')) return p.slice(2);
  return p;
}

// ══════ AUTH ══════
app.post('/api/auth/register', rateLimit(3, 10), async (req, res) => {
  try {
    const { phone: rawPhone, name, pin, plan, partner_phone, partner_name, business_name } = req.body;
    if (!rawPhone || !pin || pin.length !== 4) return res.status(400).json({ error: 'Teléfono y PIN de 4 dígitos requeridos' });
    const phone = normalizePhone(rawPhone);
    const { data: existing } = await supabase.from('users').select('id').eq('phone', phone).single();
    if (existing) return res.status(409).json({ error: 'Este número ya tiene cuenta' });
    const verifyCode = String(Math.floor(100000 + Math.random() * 900000));
    const verifyExpiry = Date.now() + 10 * 60 * 1000;
    const { data, error } = await supabase.from('users').insert({
      phone, name, pin, plan: plan || 'personal',
      partner_phone, partner_name, business_name,
      status: 'pending',
      verify_code: verifyCode, verify_expiry: verifyExpiry
    }).select().single();
    if (error) throw error;
    await sendWhatsApp(phone,
      `👋 ¡Hola ${name || ''}! Bienvenido a *MiCaja*\n\n` +
      `🔢 Tu código de verificación es:\n\n*${verifyCode}*\n\n⏱ Expira en 10 minutos.\nIngrésalo en la web para activar tu cuenta.`
    );
    const { pin: _, verify_code: __, ...user } = data;
    res.json({ ok: true, user, needsVerification: true });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Error al registrar' });
  }
});

app.post('/api/auth/verify', rateLimit(10, 30), async (req, res) => {
  try {
    const { phone: rawPhone, code } = req.body;
    const phone = normalizePhone(rawPhone);
    const { data: user } = await supabase.from('users').select('*').eq('phone', phone).single();
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    if (user.verify_code !== code) return res.status(401).json({ error: 'Código incorrecto' });
    if (user.verify_expiry < Date.now()) return res.status(401).json({ error: 'Código expirado. Regístrate de nuevo.' });
    await supabase.from('users').update({ status: 'active', verify_code: null, verify_expiry: null }).eq('id', user.id);
    await sendWhatsApp(phone,
      `✅ *¡Cuenta verificada!*\n\nBienvenido a MiCaja ${user.name || ''}.\n\n📱 Puedes usarme aquí por WhatsApp o desde:\n🌐 milkomercios.in/MiCaja/login.html\n\nEscribe *ayuda* para ver todo lo que puedo hacer.`
    );
    const { pin: _, verify_code: __, ...safeUser } = user;
    res.json({ ok: true, user: { ...safeUser, status: 'active' } });
  } catch (err) {
    res.status(500).json({ error: 'Error al verificar' });
  }
});

const loginAttempts = new Map();

app.post('/api/auth/login', rateLimit(10, 30), async (req, res) => {
  try {
    const { phone: rawPhone, pin } = req.body;
    if (!rawPhone || !pin) return res.status(400).json({ error: 'Teléfono y PIN requeridos' });
    const phone = normalizePhone(rawPhone);

    const attempts = loginAttempts.get(phone) || { count: 0, lockedUntil: 0 };
    const now = Date.now();

    if (attempts.lockedUntil > now) {
      const minutosRestantes = Math.ceil((attempts.lockedUntil - now) / 60000);
      return res.status(429).json({
        error: `Cuenta bloqueada temporalmente. Intenta en ${minutosRestantes} minuto${minutosRestantes > 1 ? 's' : ''}.`,
        lockedMinutes: minutosRestantes
      });
    }

    const { data: userExists } = await supabase.from('users').select('id, status').eq('phone', phone).single();

    if (!userExists) {
      return res.status(401).json({ error: 'Número o PIN incorrecto' });
    }

    const { data: user, error } = await supabase.from('users').select('*').eq('phone', phone).eq('pin', pin).single();

    if (error || !user) {
      attempts.count += 1;

      const delays = [0, 1000, 2000, 4000, 8000];
      const delayMs = delays[Math.min(attempts.count - 1, delays.length - 1)];

      if (attempts.count >= 5) {
        attempts.lockedUntil = now + 15 * 60 * 1000;
        attempts.count = 0;
        loginAttempts.set(phone, attempts);
        console.warn(`🔒 Login bloqueado: ${phone} — 5 intentos fallidos`);
        return res.status(429).json({
          error: 'Demasiados intentos fallidos. Cuenta bloqueada 15 minutos.',
          lockedMinutes: 15
        });
      }

      loginAttempts.set(phone, attempts);

      if (delayMs > 0) await new Promise(resolve => setTimeout(resolve, delayMs));

      const intentosRestantes = 5 - attempts.count;
      return res.status(401).json({
        error: `PIN incorrecto. ${intentosRestantes} intento${intentosRestantes !== 1 ? 's' : ''} restante${intentosRestantes !== 1 ? 's' : ''}.`,
        attemptsLeft: intentosRestantes
      });
    }

    loginAttempts.delete(phone);

    if (user.status === 'pending') return res.status(403).json({ error: 'Cuenta pendiente de verificación. Revisa tu WhatsApp.' });
    if (user.status === 'inactive') return res.status(403).json({ error: 'Cuenta inactiva. Contacta soporte.' });

    const hora = new Date().toLocaleString('es-CO', { timeZone: 'America/Bogota', hour: '2-digit', minute: '2-digit', day: '2-digit', month: 'short' });
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'desconocida';
    sendWhatsApp(phone,
      `🔐 *Nuevo ingreso a MiCaja*\n\n` +
      `✅ Se inició sesión en la web\n` +
      `📅 ${hora}\n` +
      `🌐 IP: ${ip}\n\n` +
      `_Si no fuiste tú, cambia tu PIN ahora:\nEscríbeme "cambiar pin 1234" (pon tus 4 dígitos)_`
    ).catch(() => {});

    const { pin: _, verify_code: __, ...safeUser } = user;
    res.json({ ok: true, user: safeUser });
  } catch (err) { res.status(500).json({ error: 'Error al ingresar' }); }
});

app.post('/api/auth/magic', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Token requerido' });

    const { data: user } = await supabase
      .from('users')
      .select('*')
      .eq('magic_token', token)
      .single();

    if (!user) return res.status(401).json({ error: 'Link inválido o ya usado' });
    if (!user.magic_token_expiry || user.magic_token_expiry < Date.now()) {
      return res.status(401).json({ error: 'Link expirado. Escribe "web" al bot para obtener uno nuevo.' });
    }

    await supabase.from('users').update({
      magic_token: null,
      magic_token_expiry: null
    }).eq('id', user.id);

    const { pin: _, verify_code: __, magic_token: ___, magic_token_expiry: ____, ...safeUser } = user;
    res.json({ ok: true, user: safeUser });
  } catch (err) { res.status(500).json({ error: 'Error al verificar token' }); }
});

app.post('/api/auth/reset-pin', rateLimit(3, 10), async (req, res) => {
  try {
    const { phone: rawPhone } = req.body;
    const phone = normalizePhone(rawPhone);
    const { data: user } = await supabase.from('users').select('id, name').eq('phone', phone).single();
    if (!user) return res.status(404).json({ error: 'No hay cuenta con ese número' });
    const newPin = String(Math.floor(1000 + Math.random() * 9000));
    await supabase.from('users').update({ pin: newPin }).eq('id', user.id);
    if (WA_TOKEN && WA_PHONE_ID) await sendWhatsApp(phone, `🔐 *MiCaja* — Tu nuevo PIN es: *${newPin}*\nCámbialo cuando ingreses.`);
    res.json({ ok: true, message: 'Nuevo PIN enviado por WhatsApp' });
  } catch (err) { res.status(500).json({ error: 'Error al restablecer PIN' }); }
});

// ══════ MOVIMIENTOS ══════
app.get('/api/movements/:userId', async (req, res) => {
  try {
    const { module, period } = req.query;
    let query = supabase.from('movements').select('*').eq('user_id', req.params.userId).order('date', { ascending: false }).limit(500);
    if (module) query = query.eq('module', module);
    if (period) query = query.eq('period_id', period);
    const { data, error } = await query;
    if (error) throw error;
    res.json({ ok: true, movements: data });
  } catch (err) { res.status(500).json({ error: 'Error al obtener movimientos' }); }
});

// ══════ DEBT CONTACTS ══════
app.get('/api/debt-contacts/:userId', async (req, res) => {
  try {
    const { data, error } = await supabase.from('debt_contacts').select('*').eq('user_id', req.params.userId).order('nombre');
    if (error) throw error;
    res.json({ ok: true, contacts: data || [] });
  } catch (err) { res.status(500).json({ error: 'Error al obtener contactos' }); }
});

app.post('/api/debt-contacts', async (req, res) => {
  try {
    const { user_id, nombre, tel, tipo, nota } = req.body;
    if (!user_id || !nombre) return res.status(400).json({ error: 'user_id y nombre requeridos' });
    const { data, error } = await supabase.from('debt_contacts').insert({ user_id, nombre, tel: tel||null, tipo: tipo||'ambos', nota: nota||null }).select().single();
    if (error) throw error;
    res.json({ ok: true, contact: data });
  } catch (err) { res.status(500).json({ error: 'Error al crear contacto' }); }
});

app.put('/api/debt-contacts/:id', async (req, res) => {
  try {
    const { nombre, tel, tipo, nota } = req.body;
    const updates = {};
    if (nombre !== undefined) updates.nombre = nombre;
    if (tel !== undefined) updates.tel = tel || null;
    if (tipo !== undefined) updates.tipo = tipo;
    if (nota !== undefined) updates.nota = nota || null;
    const { data, error } = await supabase.from('debt_contacts').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json({ ok: true, contact: data });
  } catch (err) { res.status(500).json({ error: 'Error al actualizar contacto' }); }
});

app.delete('/api/debt-contacts/:id', async (req, res) => {
  try {
    const { error } = await supabase.from('debt_contacts').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Error al eliminar contacto' }); }
});

// ══════ PDF UPLOAD ══════
app.post('/api/upload-pdf', async (req, res) => {
  try {
    const { html, filename } = req.body;
    if (!html) return res.status(400).json({ error: 'HTML requerido' });

    const token = crypto.randomBytes(16).toString('hex');
    const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

    const { data, error } = await supabase.from('temp_files').insert({
      token,
      content: html,
      filename: filename || 'informe-micaja.html',
      expires_at: expires
    }).select().single();

    if (error) throw error;

    const link = `https://micaja-backend-production.up.railway.app/api/download/${token}`;
    res.json({ ok: true, link });
  } catch (err) {
    console.error('Upload PDF error:', err.message);
    res.status(500).json({ error: err.message || 'Error al guardar informe' });
  }
});

app.get('/api/download/:token', async (req, res) => {
  try {
    const { data, error } = await supabase.from('temp_files')
      .select('*').eq('token', req.params.token).single();

    if (error || !data) return res.status(404).send(`<!DOCTYPE html><html><body style="font-family:sans-serif;text-align:center;padding:60px;color:#64748B"><h2>Archivo no encontrado</h2><p>Este link no existe o ya fue eliminado.</p></body></html>`);

    if (new Date(data.expires_at) < new Date()) {
      await supabase.from('temp_files').delete().eq('token', req.params.token);
      return res.status(410).send(`<!DOCTYPE html><html><body style="font-family:sans-serif;text-align:center;padding:60px;color:#64748B"><h2>Link expirado</h2><p>Este informe estuvo disponible por 24 horas.</p></body></html>`);
    }

    const toolbar = `<div style="position:fixed;top:0;left:0;right:0;background:#0F172A;color:#fff;padding:10px 20px;display:flex;align-items:center;justify-content:space-between;z-index:9999;font-family:sans-serif;font-size:13px">
      <span style="font-weight:700">📄 ${data.filename.replace('.html','')} · <span style="opacity:.6;font-weight:400">Informe MiCaja</span></span>
      <div style="display:flex;gap:8px">
        <button onclick="window.print()" style="padding:7px 16px;background:#25D366;color:#fff;border:none;border-radius:6px;font-weight:700;cursor:pointer;font-size:12px">⬇️ Guardar PDF</button>
        <a href="https://milkomercios.in/MiCaja" style="padding:7px 16px;background:#334155;color:#fff;border:none;border-radius:6px;font-weight:700;cursor:pointer;font-size:12px;text-decoration:none">MiCaja</a>
      </div>
    </div>
    <div style="height:46px"></div>
    <style>@media print{div[style*="position:fixed"]{display:none!important}div[style*="height:46px"]{display:none!important}}</style>`;

    const htmlWithToolbar = data.content.replace('<body>', '<body>' + toolbar);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(htmlWithToolbar);
  } catch (err) {
    res.status(500).send('Error al cargar informe');
  }
});

// ══════ SERVICIOS ══════
app.get('/api/servicios/:userId', async (req, res) => {
  try {
    const { data, error } = await supabase.from('servicios').select('*').eq('user_id', req.params.userId).order('dia');
    if (error) throw error;
    res.json({ ok: true, servicios: data || [] });
  } catch (err) { res.status(500).json({ error: 'Error al obtener servicios' }); }
});
app.post('/api/servicios', async (req, res) => {
  try {
    const { user_id, nombre, icono, dia, color, wa, pagado_mes } = req.body;
    if (!user_id || !nombre || !dia) return res.status(400).json({ error: 'Campos requeridos: user_id='+user_id+' nombre='+nombre+' dia='+dia });
    const { data, error } = await supabase.from('servicios').insert({ user_id, nombre, icono: icono||'🔔', dia: parseInt(dia), color: color||'#EFF6FF', wa: wa||null, pagado_mes: pagado_mes||false }).select().single();
    if (error) { console.error('Servicios insert error:', error); return res.status(500).json({ error: error.message }); }
    res.json({ ok: true, servicio: data });
  } catch (err) { console.error('Servicios catch:', err.message); res.status(500).json({ error: err.message }); }
});
app.put('/api/servicios/:id', async (req, res) => {
  try {
    const { nombre, icono, dia, color, wa, pagado_mes } = req.body;
    const u = {};
    if (nombre !== undefined) u.nombre = nombre;
    if (icono !== undefined) u.icono = icono;
    if (dia !== undefined) u.dia = parseInt(dia);
    if (color !== undefined) u.color = color;
    if (wa !== undefined) u.wa = wa || null;
    if (pagado_mes !== undefined) u.pagado_mes = pagado_mes;
    const { data, error } = await supabase.from('servicios').update(u).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json({ ok: true, servicio: data });
  } catch (err) { res.status(500).json({ error: 'Error al actualizar servicio' }); }
});
app.delete('/api/servicios/:id', async (req, res) => {
  try {
    const { error } = await supabase.from('servicios').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Error al eliminar servicio' }); }
});

app.get('/api/tasks/:userId', async (req, res) => {
  try {
    const { data, error } = await supabase.from('tasks').select('*').eq('user_id', req.params.userId).order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ ok: true, tasks: data || [] });
  } catch (err) { res.status(500).json({ error: 'Error al obtener tareas' }); }
});
app.post('/api/tasks', async (req, res) => {
  try {
    const { user_id, titulo, prioridad, fecha, categoria, done } = req.body;
    if (!user_id || !titulo) return res.status(400).json({ error: 'Campos requeridos' });
    const { data, error } = await supabase.from('tasks').insert({ user_id, titulo, prioridad: prioridad||'media', fecha: fecha||null, categoria: categoria||null, done: done||false }).select().single();
    if (error) throw error;
    res.json({ ok: true, task: data });
  } catch (err) { res.status(500).json({ error: 'Error al crear tarea' }); }
});
app.put('/api/tasks/:id', async (req, res) => {
  try {
    const { titulo, prioridad, fecha, categoria, done, completado } = req.body;
    const u = {};
    if (titulo !== undefined) u.titulo = titulo;
    if (prioridad !== undefined) u.prioridad = prioridad;
    if (fecha !== undefined) u.fecha = fecha || null;
    if (categoria !== undefined) u.categoria = categoria || null;
    if (done !== undefined) u.done = done;
    if (completado !== undefined) u.completado = completado || null;
    const { data, error } = await supabase.from('tasks').update(u).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json({ ok: true, task: data });
  } catch (err) { res.status(500).json({ error: 'Error al actualizar tarea' }); }
});
app.delete('/api/tasks/:id', async (req, res) => {
  try {
    const { error } = await supabase.from('tasks').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Error al eliminar tarea' }); }
});

// ══════ MERCADO ══════
app.get('/api/mercado/:userId', async (req, res) => {
  try {
    const { data, error } = await supabase.from('mercado').select('*').eq('user_id', req.params.userId).order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ ok: true, items: data || [] });
  } catch (err) { res.status(500).json({ error: 'Error al obtener lista' }); }
});
app.post('/api/mercado', async (req, res) => {
  try {
    const { user_id, nombre, cantidad, categoria, done } = req.body;
    if (!user_id || !nombre) return res.status(400).json({ error: 'Campos requeridos' });
    const { data, error } = await supabase.from('mercado').insert({ user_id, nombre, cantidad: cantidad||null, categoria: categoria||'Otros', done: done||false }).select().single();
    if (error) throw error;
    res.json({ ok: true, item: data });
  } catch (err) { res.status(500).json({ error: 'Error al crear item' }); }
});
app.put('/api/mercado/:id', async (req, res) => {
  try {
    const { done } = req.body;
    const u = {};
    if (done !== undefined) u.done = done;
    const { data, error } = await supabase.from('mercado').update(u).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json({ ok: true, item: data });
  } catch (err) { res.status(500).json({ error: 'Error al actualizar item' }); }
});
app.delete('/api/mercado/:id', async (req, res) => {
  try {
    const { error } = await supabase.from('mercado').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Error al eliminar item' }); }
});

app.post('/api/movements', async (req, res) => {
  try {
    const { user_id, type, amount, description, category, who, shared, note, date, source, module } = req.body;
    if (!user_id || !type || !amount || !description) return res.status(400).json({ error: 'Campos requeridos: user_id, type, amount, description' });
    const finalCategory = category || autoCategory(description, type);
    const { data, error } = await supabase.from('movements').insert({ user_id, type, amount, description, category: finalCategory, who, shared, note, date: date || new Date().toISOString().split('T')[0], source: source || 'web', module: module || 'personal' }).select().single();
    if (error) throw error;
    res.json({ ok: true, movement: data });
  } catch (err) { res.status(500).json({ error: 'Error al crear movimiento' }); }
});

app.put('/api/movements/:id', async (req, res) => {
  try {
    const { type, amount, description, category, date, note } = req.body;
    const updates = {};
    if (type !== undefined) updates.type = type;
    if (amount !== undefined) updates.amount = amount;
    if (description !== undefined) updates.description = description;
    if (category !== undefined) updates.category = category;
    if (date !== undefined) updates.date = date;
    if (note !== undefined) updates.note = note;
    const { data, error } = await supabase.from('movements').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json({ ok: true, movement: data });
  } catch (err) { res.status(500).json({ error: 'Error al actualizar movimiento' }); }
});

app.delete('/api/movements/:id', async (req, res) => {
  try {
    const { error } = await supabase.from('movements').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Error al eliminar' }); }
});

app.get('/api/summary/:userId', async (req, res) => {
  try {
    const { module } = req.query;
    let query = supabase.from('movements').select('*').eq('user_id', req.params.userId);
    if (module) query = query.eq('module', module);
    const { data: movs } = await query;
    const income = (movs||[]).filter(m => m.type === 'income').reduce((s,m) => s + Number(m.amount), 0);
    const expense = (movs||[]).filter(m => m.type === 'expense').reduce((s,m) => s + Number(m.amount), 0);
    const byCategory = {};
    (movs||[]).forEach(m => { if (!byCategory[m.category]) byCategory[m.category] = { income: 0, expense: 0 }; byCategory[m.category][m.type] += Number(m.amount); });
    res.json({ ok: true, summary: { income, expense, balance: income - expense, count: (movs||[]).length, byCategory } });
  } catch (err) { res.status(500).json({ error: 'Error al obtener resumen' }); }
});

// ══════ VIAJES ══════
app.post('/api/trips', async (req, res) => {
  try {
    const { user_id, name, members } = req.body;
    const { data: trip, error } = await supabase.from('trips').insert({ user_id, name, status: 'active' }).select().single();
    if (error) throw error;
    if (members && members.length > 0) {
      const rows = members.map(m => ({
        trip_id: trip.id,
        name: typeof m === 'string' ? m : m.name,
        phone: typeof m === 'object' ? (m.phone || null) : null
      }));
      await supabase.from('trip_members').insert(rows);
    }
    res.json({ ok: true, trip });
  } catch (err) { res.status(500).json({ error: 'Error al crear viaje' }); }
});

app.get('/api/trips/:userId', async (req, res) => {
  try {
    const { data } = await supabase.from('trips').select('*, trip_members(*), trip_expenses(*)').eq('user_id', req.params.userId).order('created_at', { ascending: false });
    res.json({ ok: true, trips: data || [] });
  } catch (err) { res.status(500).json({ error: 'Error al obtener viajes' }); }
});

app.post('/api/trips/:id/members', async (req, res) => {
  try {
    const { name, phone } = req.body;
    if (!name) return res.status(400).json({ error: 'Nombre requerido' });
    const { data, error } = await supabase.from('trip_members').insert({ trip_id: req.params.id, name, phone: phone || null }).select().single();
    if (error) throw error;
    res.json({ ok: true, member: data });
  } catch (err) { res.status(500).json({ error: 'Error al agregar miembro' }); }
});

app.put('/api/trips/:tripId/members/:memberId', async (req, res) => {
  try {
    const { phone, name } = req.body;
    const updates = {};
    if (phone !== undefined) updates.phone = phone;
    if (name !== undefined) updates.name = name;
    const { data, error } = await supabase.from('trip_members').update(updates).eq('id', req.params.memberId).select().single();
    if (error) throw error;
    res.json({ ok: true, member: data });
  } catch (err) { res.status(500).json({ error: 'Error al actualizar miembro' }); }
});

app.delete('/api/trips/:tripId/members/:memberId', async (req, res) => {
  try {
    await supabase.from('trip_members').delete().eq('id', req.params.memberId);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Error al eliminar miembro' }); }
});

app.put('/api/trips/:id', async (req, res) => {
  try {
    const { name, status } = req.body;
    const updates = {};
    if (name) updates.name = name;
    if (status) updates.status = status;
    const { data, error } = await supabase.from('trips').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json({ ok: true, trip: data });
  } catch (err) { res.status(500).json({ error: 'Error al actualizar' }); }
});

app.delete('/api/trips/:id', async (req, res) => {
  try {
    await supabase.from('trip_expenses').delete().eq('trip_id', req.params.id);
    await supabase.from('trip_members').delete().eq('trip_id', req.params.id);
    await supabase.from('trips').delete().eq('id', req.params.id);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Error al eliminar' }); }
});

app.post('/api/trips/:id/debt-payments', async (req, res) => {
  try {
    const { debt_key, amount, from_name, to_name } = req.body;
    const { data, error } = await supabase.from('trip_debt_payments').insert({ trip_id: req.params.id, debt_key, amount, from_name, to_name }).select().single();
    if (error) throw error;
    res.json({ ok: true, payment: data });
  } catch (err) { res.status(500).json({ error: 'Error al registrar pago' }); }
});

app.get('/api/trips/:id/debt-payments', async (req, res) => {
  try {
    const { data } = await supabase.from('trip_debt_payments').select('*').eq('trip_id', req.params.id);
    res.json({ ok: true, payments: data || [] });
  } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.post('/api/trips/recordatorio', async (req, res) => {
  try {
    const { phone, from_name, to_name, amount, total, trip_name, sender_phone } = req.body;
    const cleanPhone = phone.replace(/[\s\-\+\(\)]/g,'').replace(/^0/,'');
    const finalPhone = cleanPhone.startsWith('57') ? cleanPhone : '57' + cleanPhone;
    const pendiente = Number(amount);
    const totalOriginal = Number(total);
    const abonado = totalOriginal - pendiente;

    const msg =
      `🤖 Hola *${from_name}*, soy *MiCajaBot* 👋\n\n` +
      `Te escribo de parte de *${to_name}* para recordarte amablemente que tienes un saldo pendiente del viaje:\n\n` +
      `✈️ *${trip_name}*\n━━━━━━━━━━━━━━━━\n` +
      `💸 Deuda original: *$${totalOriginal.toLocaleString()} COP*\n` +
      (abonado > 0 ? `✅ Ya abonaste: *$${abonado.toLocaleString()} COP*\n` : '') +
      `⚠️ Saldo pendiente: *$${pendiente.toLocaleString()} COP*\n━━━━━━━━━━━━━━━━\n\n` +
      `*${to_name}* puso ese dinero de su bolsillo por ti durante el viaje.\n\n` +
      `_Para quitarte de estos recordatorios, pídele a *${to_name}* que marque la deuda como pagada en MiCaja._ 😊\n\n` +
      `_MiCaja · milkomercios.in/MiCaja_`;

    const { data: registrado } = await supabase.from('users').select('id').eq('phone', finalPhone).single();
    if (registrado) {
      await sendWhatsApp(finalPhone, msg);
      if (sender_phone) await sendWhatsApp(sender_phone, `✅ Recordatorio enviado a *${from_name}*\n💸 Saldo: $${pendiente.toLocaleString()} COP\n✈️ Viaje: *${trip_name}*`);
    } else {
      if (sender_phone) await sendWhatsApp(sender_phone, `⚠️ *${from_name}* no tiene cuenta en MiCaja.\n\n📋 *Reenvíale manualmente:*\n\n` + msg);
    }
    res.json({ ok: true, direct: !!registrado });
  } catch (err) { res.status(500).json({ error: 'Error al enviar recordatorio' }); }
});

app.post('/api/trips/:id/finalizar', async (req, res) => {
  try {
    const { user_phone, skip_notify } = req.body;
    const { data: trip } = await supabase.from('trips').select('*, trip_members(*), trip_expenses(*)').eq('id', req.params.id).single();
    if (!trip) return res.status(404).json({ error: 'Viaje no encontrado' });
    if (skip_notify) {
      await supabase.from('trips').update({ status: 'finished' }).eq('id', req.params.id);
      return res.json({ ok: true, sent: 0, total: 0 });
    }
    const members = trip.trip_members || [];
    const expenses = trip.trip_expenses || [];
    const total = expenses.reduce((s, e) => s + Number(e.amount), 0);
    const balances = {};
    members.forEach(m => balances[m.name] = 0);
    expenses.forEach(exp => {
      balances[exp.payer] = (balances[exp.payer] || 0) + Number(exp.amount);
      const split = exp.split_between || members.map(m => m.name);
      const share = Number(exp.amount) / split.length;
      split.forEach(n => { balances[n] = (balances[n] || 0) - share; });
    });
    const debts = [];
    const dc = Object.entries(balances).filter(([,v]) => v < 0).sort((a,b) => a[1]-b[1]).map(([n,v]) => [n,v]);
    const cc = Object.entries(balances).filter(([,v]) => v > 0).sort((a,b) => b[1]-a[1]).map(([n,v]) => [n,v]);
    let i=0, j=0;
    while (i < dc.length && j < cc.length) {
      const amt = Math.min(-dc[i][1], cc[j][1]);
      if (amt > 1) debts.push({ from: dc[i][0], to: cc[j][0], amount: Math.round(amt) });
      dc[i][1] += amt; cc[j][1] -= amt;
      if (Math.abs(dc[i][1]) < 1) i++;
      if (Math.abs(cc[j][1]) < 1) j++;
    }
    const fecha = new Date().toLocaleDateString('es-CO', { day:'2-digit', month:'long', year:'numeric' });
    const phonesSent = [];
    const phonesNoReg = [];
    for (const member of members) {
      if (!member.phone) continue;
      const rawPhone = member.phone.replace(/[\s\-\+\(\)]/g,'').replace(/^0/,'');
      const finalPhone = rawPhone.startsWith('57') ? rawPhone : '57' + rawPhone;
      const { data: registrado } = await supabase.from('users').select('id,name').eq('phone', finalPhone).single();
      const myBalance = Math.round(balances[member.name] || 0);
      const myDebts = debts.filter(d => d.from === member.name);
      const myCredits = debts.filter(d => d.to === member.name);
      let msg = `✈️ *Resumen del viaje: ${trip.name}*\n📅 ${fecha}\n━━━━━━━━━━━━━\nHola *${member.name}*!\n\n`;
      msg += `💰 Gasto total: *$${total.toLocaleString()}*\n📊 Tu balance: *${myBalance>=0?'+':''}$${myBalance.toLocaleString()}*\n\n`;
      if (myDebts.length) { msg += `💸 *Debes pagarle a:*\n`; myDebts.forEach(d => { msg += `  • ${d.to}: $${d.amount.toLocaleString()}\n`; }); msg += '\n'; }
      if (myCredits.length) { msg += `💵 *Te deben pagarte:*\n`; myCredits.forEach(d => { msg += `  • ${d.from}: $${d.amount.toLocaleString()}\n`; }); msg += '\n'; }
      if (!myDebts.length && !myCredits.length) msg += `✅ ¡Estás al día!\n\n`;
      msg += `_Enviado desde MiCaja · milkomercios.in/MiCaja_`;
      if (registrado) {
        await sendWhatsApp(finalPhone, msg);
        phonesSent.push(member.name);
      } else {
        const templateName = process.env.WA_TEMPLATE_RESUMEN;
        if (templateName) {
          const myDebtsText = myDebts.length ? myDebts.map(d=>`Debes a ${d.to}: $${d.amount.toLocaleString()}`).join(', ') : myCredits.length ? myCredits.map(d=>`${d.from} te debe: $${d.amount.toLocaleString()}`).join(', ') : 'Estás al día ✅';
          await sendWhatsAppTemplate(finalPhone, templateName, [member.name, trip.name, '$'+total.toLocaleString(), (myBalance>=0?'+':'')+'$'+myBalance.toLocaleString(), myDebtsText]);
          phonesSent.push(member.name);
        } else {
          phonesNoReg.push({ name: member.name, phone: finalPhone, msg });
        }
      }
    }
    if (user_phone) {
      let orgMsg = `🏁 *Viaje "${trip.name}" finalizado*\n💰 Total: *$${total.toLocaleString()}*\n\n`;
      if (phonesSent.length) orgMsg += `✅ Enviado a:\n${phonesSent.map(n=>`  • ${n}`).join('\n')}\n\n`;
      if (phonesNoReg.length) { orgMsg += `⚠️ Sin cuenta MiCaja — reenvía manualmente:\n\n`; phonesNoReg.forEach(p => { orgMsg += `👤 *${p.name}* (${p.phone}):\n${p.msg}\n\n`; }); }
      if (!phonesSent.length && !phonesNoReg.length) orgMsg += `(Sin participantes con número registrado)`;
      await sendWhatsApp(user_phone, orgMsg);
    }
    await supabase.from('trips').update({ status: 'finished' }).eq('id', req.params.id);
    res.json({ ok: true, sent: phonesSent.length, noReg: phonesNoReg.length, total });
  } catch (err) { console.error('Finalizar error:', err); res.status(500).json({ error: 'Error al finalizar viaje' }); }
});

app.post('/api/trips/:tripId/expenses', async (req, res) => {
  try {
    const { description, amount, category, payer, split_between, notes, expense_date } = req.body;
    const { data, error } = await supabase.from('trip_expenses').insert({ trip_id: req.params.tripId, description, amount, category: category || 'General', payer, split_between, notes: notes || null, expense_date: expense_date || new Date().toISOString().split('T')[0] }).select().single();
    if (error) throw error;
    res.json({ ok: true, expense: data });
  } catch (err) { res.status(500).json({ error: 'Error al agregar gasto' }); }
});

app.put('/api/trips/:tripId/expenses/:expId', async (req, res) => {
  try {
    const { description, amount, category, payer, split_between, notes, expense_date } = req.body;
    const updates = {};
    if (description !== undefined) updates.description = description;
    if (amount !== undefined) updates.amount = amount;
    if (category !== undefined) updates.category = category;
    if (payer !== undefined) updates.payer = payer;
    if (split_between !== undefined) updates.split_between = split_between;
    if (notes !== undefined) updates.notes = notes;
    if (expense_date !== undefined) updates.expense_date = expense_date;
    const { data, error } = await supabase.from('trip_expenses').update(updates).eq('id', req.params.expId).select().single();
    if (error) throw error;
    res.json({ ok: true, expense: data });
  } catch (err) { res.status(500).json({ error: 'Error al editar gasto' }); }
});

app.delete('/api/trips/:tripId/expenses/:expId', async (req, res) => {
  try {
    await supabase.from('trip_expenses').delete().eq('id', req.params.expId);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Error al eliminar gasto' }); }
});

app.delete('/api/trips/:id/debt-payments', async (req, res) => {
  try {
    const { debt_key } = req.body;
    await supabase.from('trip_debt_payments').delete().eq('trip_id', req.params.id).eq('debt_key', debt_key);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Error al desmarcar' }); }
});

app.get('/api/trips/:tripId/balance', async (req, res) => {
  try {
    const { data: expenses } = await supabase.from('trip_expenses').select('*').eq('trip_id', req.params.tripId);
    const { data: members } = await supabase.from('trip_members').select('*').eq('trip_id', req.params.tripId);
    const balances = {};
    (members||[]).forEach(m => { balances[m.name] = 0; });
    (expenses||[]).forEach(exp => {
      const share = exp.amount / exp.split_between.length;
      balances[exp.payer] = (balances[exp.payer]||0) + exp.amount;
      exp.split_between.forEach(name => { balances[name] = (balances[name]||0) - share; });
    });
    const debts = [];
    const debtors = Object.entries(balances).filter(([_,v]) => v < 0).sort((a,b) => a[1]-b[1]);
    const creditors = Object.entries(balances).filter(([_,v]) => v > 0).sort((a,b) => b[1]-a[1]);
    let i=0, j=0;
    while (i < debtors.length && j < creditors.length) {
      const amount = Math.min(-debtors[i][1], creditors[j][1]);
      if (amount > 0) debts.push({ from: debtors[i][0], to: creditors[j][0], amount: Math.round(amount) });
      debtors[i][1] += amount; creditors[j][1] -= amount;
      if (Math.abs(debtors[i][1]) < 1) i++; if (Math.abs(creditors[j][1]) < 1) j++;
    }
    res.json({ ok: true, balances, debts, total: (expenses||[]).reduce((s,e) => s + Number(e.amount), 0) });
  } catch (err) { res.status(500).json({ error: 'Error al calcular balance' }); }
});

// ══════════════════════════════════════
// MÉTODOS DE PAGO
// ══════════════════════════════════════
app.get('/api/payment-methods/:userId', async (req, res) => {
  try {
    const { data } = await supabase.from('payment_methods').select('*').eq('user_id', req.params.userId).order('created_at', { ascending: false });
    res.json({ ok: true, methods: data || [] });
  } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.post('/api/payment-methods', async (req, res) => {
  try {
    const { user_id, tipo, numero, titular, descripcion, banco } = req.body;
    if (!user_id || !tipo || !numero || !titular) return res.status(400).json({ error: 'Campos requeridos' });
    const { data, error } = await supabase.from('payment_methods').insert({ user_id, tipo, numero, titular, descripcion: descripcion||null, banco: banco||null }).select().single();
    if (error) throw error;
    res.json({ ok: true, method: data });
  } catch (err) { res.status(500).json({ error: 'Error al guardar' }); }
});

app.delete('/api/payment-methods/:id', async (req, res) => {
  try {
    await supabase.from('payment_methods').delete().eq('id', req.params.id);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.post('/api/payment-methods/:userId/token', async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('id, name, pay_token').eq('id', req.params.userId).single();
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    if (user.pay_token) return res.json({ ok: true, token: user.pay_token });
    const token = crypto.randomBytes(12).toString('hex');
    await supabase.from('users').update({ pay_token: token }).eq('id', req.params.userId);
    res.json({ ok: true, token });
  } catch (err) { res.status(500).json({ error: 'Error al generar token' }); }
});

app.post('/api/payment-methods/:userId/token/reset', async (req, res) => {
  try {
    const token = crypto.randomBytes(12).toString('hex');
    await supabase.from('users').update({ pay_token: token }).eq('id', req.params.userId);
    res.json({ ok: true, token });
  } catch (err) { res.status(500).json({ error: 'Error al regenerar token' }); }
});

app.get('/api/pagos-publico/:token', async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('id, name, phone').eq('pay_token', req.params.token).single();
    if (!user) return res.status(404).json({ error: 'Link no válido o expirado' });
    const { data: methods } = await supabase.from('payment_methods').select('tipo, numero, titular, descripcion, banco').eq('user_id', user.id).order('created_at', { ascending: false });
    res.json({ ok: true, name: user.name, methods: methods || [] });
  } catch (err) { res.status(500).json({ error: 'Error' }); }
});

// ══════════════════════════════════════
// AMIGOS VIAJEROS
// ══════════════════════════════════════
app.get('/api/travel-friends/:userId', async (req, res) => {
  try {
    const { data } = await supabase.from('travel_friends').select('*').eq('user_id', req.params.userId).order('name');
    res.json({ ok: true, friends: data || [] });
  } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.post('/api/travel-friends', async (req, res) => {
  try {
    const { user_id, name, phone } = req.body;
    if (!user_id || !name) return res.status(400).json({ error: 'Campos requeridos' });
    const { data, error } = await supabase.from('travel_friends').upsert({ user_id, name, phone: phone||null }, { onConflict: 'user_id,name' }).select().single();
    if (error) throw error;
    res.json({ ok: true, friend: data });
  } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.put('/api/travel-friends/:id', async (req, res) => {
  try {
    const { name, phone } = req.body;
    const updates = {};
    if (name !== undefined) updates.name = name;
    if (phone !== undefined) updates.phone = phone;
    const { data, error } = await supabase.from('travel_friends').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json({ ok: true, friend: data });
  } catch (err) { res.status(500).json({ error: 'Error al actualizar amigo' }); }
});

app.delete('/api/travel-friends/:id', async (req, res) => {
  try {
    await supabase.from('travel_friends').delete().eq('id', req.params.id);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.post('/api/trips/:id/presupuesto', async (req, res) => {
  try {
    const { budget_per_person, categories, members, trip_name } = req.body;
    const total = budget_per_person * (members||[]).length;
    const sent = [];
    for (const mp of (members||[])) {
      if (!mp.phone) continue;
      const phone = mp.phone.replace(/[\s\-\+\(\)]/g,'').replace(/^0/,'');
      const finalPhone = phone.startsWith('57') ? phone : '57'+phone;
      const catLines = (categories||[]).map(c => `  • ${c.name}: $${Number(c.amount).toLocaleString()} COP`).join('\n');
      const msg = `📋 *Presupuesto estimado — ${trip_name}*\n\nHola *${mp.name}*! 👋\n\n💰 *Por persona: $${Number(budget_per_person).toLocaleString()} COP*\n\n${catLines ? `📊 *Desglose:*\n${catLines}\n\n` : ''}💸 Total grupo (${members.length} personas): *$${total.toLocaleString()} COP*\n\n_Presupuesto estimado — los gastos reales se registrarán en MiCaja._ ✈️`;
      await sendWhatsApp(finalPhone, msg);
      sent.push(mp.name);
    }
    res.json({ ok: true, sent });
  } catch (err) { res.status(500).json({ error: 'Error al enviar presupuesto' }); }
});

// ══════ WHATSAPP WEBHOOK ══════
app.get('/webhook', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];
  if (mode === 'subscribe' && token === WA_VERIFY_TOKEN) { console.log('✅ Webhook verificado'); res.status(200).send(challenge); }
  else res.sendStatus(403);
});

app.post('/webhook', async (req, res) => {
  try {
    const body = req.body;
    if (body.object !== 'whatsapp_business_account') return res.sendStatus(404);
    const messages = body.entry?.[0]?.changes?.[0]?.value?.messages;
    if (!messages || messages.length === 0) return res.sendStatus(200);
    const msg = messages[0];
    const from = msg.from;

    const waLimit = rateLimitWA(from);
    if (waLimit.blocked) {
      console.warn(`⚠️ WA rate limit (${waLimit.reason}): ${from}`);
      if (waLimit.reason === 'dia') await sendWhatsApp(from, `⚠️ Has alcanzado el límite de mensajes por hoy. Intenta mañana o usa la web: milkomercios.in/MiCaja`);
      return res.sendStatus(200);
    }

    if (msg.type === 'audio' || msg.type === 'voice') {
      await sendWhatsApp(from, `🎤 No proceso mensajes de voz todavía.\n\nEscríbeme así:\n💸 _"pagué luz 80mil"_\n💵 _"me ingresaron 200mil"_`);
      return res.sendStatus(200);
    }
    if (msg.type === 'image' || msg.type === 'video' || msg.type === 'document' || msg.type === 'sticker') {
      await sendWhatsApp(from, `📎 Solo proceso mensajes de texto por ahora 😊`);
      return res.sendStatus(200);
    }
    const text = msg.text?.body?.trim();
    if (!text) return res.sendStatus(200);
    console.log(`📱 WhatsApp de ${from}: ${text}`);
    await processWhatsAppMessage(from, text);
    res.sendStatus(200);
  } catch (err) { console.error('Webhook error:', err); res.sendStatus(200); }
});

// ══════════════════════════════════════
// FUNCIÓN GLOBAL DE SESIÓN — única fuente de verdad
// FIX v2.2: siempre upsert por phone, nunca merge con estado viejo
// ══════════════════════════════════════
async function setCtxByPhone(phone, newCtx) {
  // IMPORTANTE: siempre sobrescribe — nunca mezcla con contexto anterior
  await supabase.from('wa_sessions').upsert(
    {
      phone,
      context: JSON.stringify(newCtx),
      last_message: null,
      updated_at: new Date().toISOString()
    },
    { onConflict: 'phone' }
  );
}

async function getCtxByPhone(phone) {
  const { data: session } = await supabase.from('wa_sessions').select('context').eq('phone', phone).single();
  if (!session || !session.context) return {};
  try { return JSON.parse(session.context); } catch { return {}; }
}

// ══════════════════════════════════════
// PROCESAR MENSAJES DE WHATSAPP
// ══════════════════════════════════════
async function processWhatsAppMessage(phone, text) {
  let { data: user } = await supabase.from('users').select('*').eq('phone', phone).single();

  const lower = text.toLowerCase().trim()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[¿¡]/g, '');

  // ── Leer contexto fresco desde DB ──
  // FIX: siempre leer directo de DB, no usar variable local que puede quedar desincronizada
  const ctx = await getCtxByPhone(phone);

  // Helpers locales que usan la función global
  const setCtx = (newCtx) => setCtxByPhone(phone, newCtx);
  const clearCtx = () => setCtxByPhone(phone, {});

  // ══════ REGISTRO SI NO TIENE CUENTA ══════
  if (!user && ['registrar','registro','registrarme','empezar','comenzar','crear cuenta','nueva cuenta','quiero registrarme'].includes(lower)) {
    await setCtx({ step: 'register_plan' });
    await sendWhatsApp(phone, `🎉 ¡Bienvenido a *MiCaja*!\n\n¿Para qué quieres usarla?\n\n*1.* 👤 Personal\n*2.* 💑 Pareja\n*3.* ✈️ Viajes\n*4.* 🏪 Negocio\n\nResponde con el número`);
    return;
  }
  if (!user && ctx.step === 'register_plan') {
    const planMap = {'1':'personal','2':'parejas','3':'viajes','4':'comerciantes','personal':'personal','pareja':'parejas','parejas':'parejas','viaje':'viajes','viajes':'viajes','negocio':'comerciantes','comercio':'comerciantes'};
    const plan = planMap[lower];
    if (!plan) { await sendWhatsApp(phone, `Solo responde *1*, *2*, *3* o *4* 😊`); return; }
    await setCtx({ step: 'register_name', plan });
    await sendWhatsApp(phone, `¿Cómo te llamas? ✍️`);
    return;
  }
  if (!user && ctx.step === 'register_name') {
    const name = text.trim();
    const plan = ctx.plan || 'personal';
    const pin = String(Math.floor(1000 + Math.random() * 9000));
    const { data: newUser, error } = await supabase.from('users').insert({ phone, name, pin, plan }).select().single();
    if (!error && newUser) {
      await clearCtx();
      const planNames = {personal:'👤 Personal',parejas:'💑 Pareja',viajes:'✈️ Viajes',comerciantes:'🏪 Negocio'};
      await sendWhatsApp(phone, `✅ *¡Listo ${name}!*\n\n📋 Plan: ${planNames[plan]}\n🔐 Tu PIN: *${pin}* (guárdalo para la web)\n\n💸 _"pagué arriendo 800mil"_\n💵 _"me pagaron 2 millones"_\n📊 _"cómo voy?"_\n\n¡Empecemos! 🚀`);
    } else { await clearCtx(); await sendWhatsApp(phone, `Algo falló. Escribe *registrar* para intentar de nuevo.`); }
    return;
  }
  if (!user) {
    await sendWhatsApp(phone, `👋 ¡Hola! Soy *MiCajaBot* 🤖\n\nEscribe *registrarme* y te ayudo a crear tu cuenta en 30 segundos 🚀`);
    return;
  }

  // ══════ COMANDOS GLOBALES — siempre funcionan, limpian contexto primero ══════
  // FIX: estos comandos van ANTES de cualquier evaluación de ctx.step
  const esReset = ['cancelar','cancel','reset','reiniciar','limpiar','salir','exit'].includes(lower);
  if (esReset) {
    await clearCtx();
    await sendWhatsApp(phone, `✅ Listo, contexto limpiado.\n\nEscribe *hola* o *menu* para empezar 😊`);
    return;
  }

  // ══════ SALUDO — limpia contexto y muestra balance ══════
  if (['hola','hi','hey','buenas','buenos dias','buenas tardes','buenas noches','que mas','inicio','start'].includes(lower)) {
    await clearCtx();
    const hour = new Date(new Date().toLocaleString('en-US',{timeZone:'America/Bogota'})).getHours();
    const saludo = hour < 12 ? 'Buenos dias' : hour < 18 ? 'Buenas tardes' : 'Buenas noches';
    const planNames = {personal:'👤 Personal',parejas:'💑 Pareja',viajes:'✈️ Viajes',comerciantes:'🏪 Negocio'};
    const { data: movs } = await supabase.from('movements').select('type, amount').eq('user_id', user.id).eq('module', user.plan);
    const bal = (movs||[]).reduce((s,m) => s + (m.type==='income' ? Number(m.amount) : -Number(m.amount)), 0);
    await sendWhatsApp(phone,
      `${saludo} *${user.name||''}* 👋\n\n` +
      `Modulo activo: *${planNames[user.plan]}*\n` +
      `${movs&&movs.length ? `Balance: *$${bal.toLocaleString()}* COP\n` : ''}\n` +
      `Escribe *menu* para ver todas las opciones\n` +
      `O registra directamente:\n` +
      `💸 _"pague luz 80mil"_\n` +
      `💵 _"me ingresaron 2 millones"_`
    );
    return;
  }

  // ══════ MENÚ PRINCIPAL ══════
  // FIX: detectar "menu" SIN depender del ctx anterior — siempre funciona
  const esMenu = ['menu','menues','opciones','que puedes hacer','comandos','ayuda','help','inicio menu','volver','volver al menu','0'].includes(lower);
  if (esMenu) {
    await clearCtx();
    const planNames = {personal:'👤 Personal',parejas:'💑 Pareja',viajes:'✈️ Viajes',comerciantes:'🏪 Negocio'};
    await sendWhatsApp(phone,
      `🤖 *MiCaja — Menu principal*\n` +
      `Modulo activo: *${planNames[user.plan]}*\n\n` +
      `*1* 💰 Finanzas personales\n` +
      `*2* 🏪 Mi negocio\n` +
      `*3* 💑 Pareja\n` +
      `*4* ✈️ Viajes\n` +
      `*5* 💸 Deudas\n` +
      `*6* 💳 Metodos de pago\n` +
      `*7* 🛒 Lista de mercado\n` +
      `*8* ✅ Tareas\n` +
      `*9* 🔔 Servicios y pagos\n` +
      `*10* 📊 Informes\n\n` +
      `Escribe el numero o el nombre del modulo`
    );
    // FIX: setCtx DESPUÉS de enviar el mensaje, con contexto limpio
    await setCtx({ step: 'menu_principal' });
    return;
  }

  // ══════ PIN ══════
  const pinConsulta = /^(mi\s+)?pin$|^(cuál|cual)\s+es\s+mi\s+pin|^(olvidé|olvide|recuperar|recordar|ver)\s+(mi\s+)?pin|^pin\?$/i;
  if (pinConsulta.test(lower)) {
    await sendWhatsApp(phone, `🔐 Tu PIN es: *${user.pin}*\n\nPara cambiarlo: _"cambiar pin 1234"_`);
    return;
  }
  const pinCambio = lower.match(/(?:cambiar\s+pin|nuevo\s+pin|pin\s+nuevo|mi\s+pin\s+es)\s*(\d{4})/i) || lower.match(/^pin\s+(\d{4})$/i);
  if (pinCambio) {
    await supabase.from('users').update({ pin: pinCambio[1] }).eq('id', user.id);
    await sendWhatsApp(phone, `✅ PIN cambiado a *${pinCambio[1]}* 🔒`);
    return;
  }

  // ══════ MÓDULO — consultar y cambiar ══════
  const esConsultaModulo = /^(mi\s+)?modulo(\s+actual|\s+activo)?$|^en\s+que\s+modulo|^que\s+modulo|^modulos\s+disponibles?|^ver\s+modulos?|^mis\s+modulos?/i.test(lower);
  if (esConsultaModulo) {
    const planNames = {personal:'👤 Personal',parejas:'💑 Pareja',viajes:'✈️ Viajes',comerciantes:'🏪 Negocio'};
    const actual = planNames[user.plan] || '👤 Personal';
    await sendWhatsApp(phone,
      `📋 *Módulo activo: ${actual}*\n\n` +
      `Elige otro módulo:\n` +
      `*1* 👤 Personal — finanzas del día a día\n` +
      `*2* 🏪 Negocio — ventas y gastos del negocio\n` +
      `*3* 💑 Pareja — gastos compartidos\n` +
      `*4* ✈️ Viajes — gastos de un viaje\n\n` +
      `Responde con el número o escribe:\n` +
      `_"modulo personal"_ · _"modulo negocio"_ · _"modulo pareja"_ · _"modulo viajes"_`
    );
    await setCtx({step:'select_modulo'});
    return;
  }
  if (ctx.step === 'select_modulo') {
    const opMap = {'1':'personal','2':'comerciantes','3':'parejas','4':'viajes'};
    const planMap = {
      personal:'personal',finanzas:'personal','mis finanzas':'personal',
      pareja:'parejas',parejas:'parejas',
      viaje:'viajes',viajes:'viajes',
      negocio:'comerciantes',comercio:'comerciantes',comerciante:'comerciantes','mi negocio':'comerciantes'
    };
    const plan = opMap[lower] || planMap[lower];
    if (plan) {
      await supabase.from('users').update({plan}).eq('id', user.id);
      await clearCtx();
      const planNames = {personal:'👤 Personal',parejas:'💑 Pareja',viajes:'✈️ Viajes',comerciantes:'🏪 Negocio'};
      await sendWhatsApp(phone, `✅ *Módulo cambiado a ${planNames[plan]}* 💪\n\nAhora todos tus movimientos se guardan en este módulo.\n_Escribe "como voy" para ver tu balance_`);
    } else {
      await sendWhatsApp(phone, `Responde *1* Personal, *2* Negocio, *3* Pareja o *4* Viajes\nO escribe _"modulo negocio"_ etc.`);
    }
    return;
  }
  const moduloMatch = lower.match(/^(?:modulo|cambiar\s+modulo|cambiar\s+a|quiero\s+el\s+modulo|quiero\s+modulo|usar\s+modulo)\s+(.+)/i);
  if (moduloMatch) {
    const planMap = {
      personal:'personal',finanzas:'personal','mis finanzas':'personal',
      pareja:'parejas',parejas:'parejas',
      viaje:'viajes',viajes:'viajes',
      negocio:'comerciantes',comercio:'comerciantes',comerciante:'comerciantes','mi negocio':'comerciantes'
    };
    const plan = planMap[moduloMatch[1].trim().toLowerCase()];
    if (plan) {
      await supabase.from('users').update({plan}).eq('id', user.id);
      const planNames = {personal:'👤 Personal',parejas:'💑 Pareja',viajes:'✈️ Viajes',comerciantes:'🏪 Negocio'};
      await sendWhatsApp(phone, `✅ Módulo cambiado a *${planNames[plan]}* 💪`);
    } else {
      await sendWhatsApp(phone, `Módulos disponibles:\n*personal* · *pareja* · *viajes* · *negocio*\n\nEjemplo: _"modulo negocio"_`);
    }
    return;
  }

  // ══════ TAREAS ══════
  if (/mis\s+tareas?|ver\s+tareas?|tareas?\s+pendientes?|que\s+tengo\s+pendiente|lista\s+de\s+tareas?/i.test(lower)) {
    const {data:tareas} = await supabase.from('tasks').select('*').eq('user_id',user.id).eq('done',false).order('prioridad').limit(10);
    if (!tareas||!tareas.length) {
      await sendWhatsApp(phone, `✅ *Tareas pendientes*\n\n¡No tienes tareas pendientes! 🎉\n\n_Agrega desde la web: milkomercios.in/MiCaja/tareas.html_`);
    } else {
      const priIcon = {alta:'🔴',media:'🟡',baja:'🔵'};
      const lista = tareas.map(t=>`${priIcon[t.prioridad]||'⚪'} ${t.titulo}${t.fecha?' ('+t.fecha+')':''}`).join('\n');
      await sendWhatsApp(phone, `✅ *Tareas pendientes (${tareas.length})*\n\n${lista}\n\n_Gestiona desde la web: milkomercios.in/MiCaja/tareas.html_`);
    }
    return;
  }

  // ══════ LISTA DE MERCADO ══════
  if (/mi\s+(?:lista\s+de\s+)?mercado|lista\s+(?:del\s+)?mercado|que\s+necesito\s+comprar|mis\s+compras?|lista\s+compras?/i.test(lower)) {
    const {data:items} = await supabase.from('mercado').select('*').eq('user_id',user.id).eq('done',false).order('created_at',{ascending:false}).limit(15);
    if (!items||!items.length) {
      await sendWhatsApp(phone, `🛒 *Lista de mercado*\n\n¡Tu lista está vacía! 🎉\n\n_Agrega productos desde la web: milkomercios.in/MiCaja/mercado.html_`);
    } else {
      const porCat = {};
      items.forEach(i=>{const c=i.categoria||'Otros';porCat[c]=(porCat[c]||[]).concat(i);});
      let msg = `🛒 *Lista de mercado (${items.length} productos)*\n\n`;
      Object.keys(porCat).forEach(cat=>{
        msg += `*${cat}*\n`;
        porCat[cat].forEach(i=>{ msg += `  ☐ ${i.nombre}${i.cantidad?' ('+i.cantidad+')':''}\n`; });
        msg += '\n';
      });
      msg += `_Marca como comprado en: milkomercios.in/MiCaja/mercado.html_`;
      await sendWhatsApp(phone, msg);
    }
    return;
  }

  // ══════ SERVICIOS PÚBLICOS ══════
  if (/mis\s+servicios?|servicios?\s+publicos?|cuales\s+son\s+mis\s+servicios?|vencimientos?|que\s+vence|pagos?\s+pendientes?\s+(?:del\s+)?mes/i.test(lower)) {
    const {data:servs} = await supabase.from('servicios').select('*').eq('user_id',user.id).order('dia');
    if (!servs||!servs.length) {
      await sendWhatsApp(phone, `🔔 *Servicios*\n\nNo tienes servicios configurados.\n\n_Configura desde la web: milkomercios.in/MiCaja/servicios.html_`);
      return;
    }
    const hoy = new Date(); hoy.setHours(0,0,0,0);
    const diaHoy = hoy.getDate();
    let vencidos=[], proximos=[], resto=[];
    servs.forEach(s=>{
      if(s.pagado_mes){resto.push(s);return;}
      const diff = s.dia - diaHoy;
      if(diff < 0) vencidos.push({s,diff});
      else if(diff <= 5) proximos.push({s,diff});
      else resto.push(s);
    });
    let msg = `🔔 *Mis servicios y pagos*\n\n`;
    if(vencidos.length){
      msg += `*⚠️ VENCIDOS (${vencidos.length}):*\n`;
      vencidos.forEach(({s,diff})=>{ msg += `  ${s.icono} ${s.nombre} — venció hace ${Math.abs(diff)} día${Math.abs(diff)!==1?'s':''}\n`; });
      msg += '\n';
    }
    if(proximos.length){
      msg += `*📅 PRÓXIMOS (${proximos.length}):*\n`;
      proximos.forEach(({s,diff})=>{ msg += `  ${s.icono} ${s.nombre} — ${diff===0?'HOY':'en '+diff+' día'+(diff!==1?'s':'')}\n`; });
      msg += '\n';
    }
    const pagados = servs.filter(s=>s.pagado_mes);
    if(pagados.length) msg += `*✅ Pagados este mes (${pagados.length}):*\n${pagados.map(s=>`  ${s.icono} ${s.nombre}`).join('\n')}\n\n`;
    msg += `_Gestiona en: milkomercios.in/MiCaja/servicios.html_`;
    await sendWhatsApp(phone, msg);
    return;
  }

  // ══════ DEUDAS ══════
  if (/mis\s+deudas?|ver\s+deudas?|cuanto\s+(?:me\s+)?debo|estado\s+deudas?|deudas?\s+pendientes?|quien(?:es)?\s+me\s+deben?|a\s+quien(?:es)?\s+(?:le\s+)?debo/i.test(lower)) {
    const {data:deudas} = await supabase.from('debts').select('*').eq('user_id',user.id).neq('status','paid');
    if (!deudas||!deudas.length) {
      await sendWhatsApp(phone, `💸 *Deudas*\n\n¡No tienes deudas activas! 🎉\n\n_Registra desde la web: milkomercios.in/MiCaja/deudas.html_`);
      return;
    }
    const meDeben = deudas.filter(d=>d.type==='me_deben');
    const yoDebo = deudas.filter(d=>d.type==='debo');
    const totalMD = meDeben.reduce((s,d)=>s+Number(d.amount)-(Number(d.paid)||0),0);
    const totalYD = yoDebo.reduce((s,d)=>s+Number(d.amount)-(Number(d.paid)||0),0);
    let msg = `💸 *Estado de deudas*\n\n`;
    msg += `💰 *Me deben:* $${totalMD.toLocaleString()}\n`;
    msg += `💳 *Yo debo:* $${totalYD.toLocaleString()}\n`;
    msg += `${totalMD>=totalYD?'✅':'⚠️'} *Balance:* ${totalMD>=totalYD?'+':''}$${(totalMD-totalYD).toLocaleString()}\n\n`;
    if(meDeben.length){
      msg += `*Me deben (${meDeben.length}):*\n`;
      meDeben.forEach(d=>{const p=Number(d.amount)-(Number(d.paid)||0);msg+=`  👤 ${d.person_name}: $${p.toLocaleString()}\n`;});
      msg += '\n';
    }
    if(yoDebo.length){
      msg += `*Yo debo (${yoDebo.length}):*\n`;
      yoDebo.forEach(d=>{const p=Number(d.amount)-(Number(d.paid)||0);msg+=`  👤 ${d.person_name}: $${p.toLocaleString()}\n`;});
      msg += '\n';
    }
    msg += `_Gestiona en: milkomercios.in/MiCaja/deudas.html_`;
    await sendWhatsApp(phone, msg);
    return;
  }

  // ══════ MÉTODOS DE PAGO ══════
  if (/mi\s+nequi|mi\s+bancol|mi\s+daviplata|mi\s+banco|mis\s+datos?\s+(?:de\s+)?pago|mis\s+llaves?|como\s+me\s+pagan|datos?\s+(?:para\s+)?transferencia|mi\s+cuenta|mi\s+numero\s+(?:de\s+)?cuenta|mis\s+metodos?\s+(?:de\s+)?pago/i.test(lower)) {
    const {data:cfg} = await supabase.from('user_configs').select('*').eq('user_id',user.id).single();
    const nequi = cfg?.nequi;
    const bancol = cfg?.bancolombia;
    const daviplata = cfg?.daviplata;
    const otro = cfg?.otro_pago;
    if (!nequi && !bancol && !daviplata && !otro) {
      await sendWhatsApp(phone,
        `💳 *Métodos de pago*\n\n` +
        `No tienes datos de pago guardados.\n\n` +
        `Para guardarlos escribe:\n` +
        `_"mi nequi es 3001234567"_\n` +
        `_"mi bancolombia es 12345678901 tipo ahorros"_\n` +
        `_"mi daviplata es 3001234567"_`
      );
    } else {
      let msg = `💳 *Tus datos de pago*\n\n`;
      if(nequi) msg += `📱 *Nequi:* ${nequi}\n`;
      if(daviplata) msg += `📱 *Daviplata:* ${daviplata}\n`;
      if(bancol) msg += `🏦 *Bancolombia:* ${bancol}\n`;
      if(otro) msg += `💰 *Otro:* ${otro}\n`;
      msg += `\n_Actualiza en: milkomercios.in/MiCaja_`;
      await sendWhatsApp(phone, msg);
    }
    return;
  }

  // ══════ GUARDAR MÉTODOS DE PAGO ══════
  const nequiMatch = lower.match(/mi\s+nequi\s+(?:es\s+|:?\s*)([\d\s]+)/i);
  const bancolMatch = lower.match(/mi\s+bancol(?:ombia)?\s+(?:es\s+|:?\s*)([\d\s]+)/i);
  const daviMatch = lower.match(/mi\s+daviplata\s+(?:es\s+|:?\s*)([\d\s]+)/i);
  const otroMatch = lower.match(/mi\s+(?:otro\s+)?pago\s+(?:es\s+|:?\s*)(.+)/i);
  if (nequiMatch||bancolMatch||daviMatch||otroMatch) {
    const updates = {};
    if(nequiMatch) updates.nequi = nequiMatch[1].trim().replace(/\s+/g,'');
    if(bancolMatch) updates.bancolombia = bancolMatch[1].trim().replace(/\s+/g,'');
    if(daviMatch) updates.daviplata = daviMatch[1].trim().replace(/\s+/g,'');
    if(otroMatch) updates.otro_pago = otroMatch[1].trim();
    updates.user_id = user.id;
    await supabase.from('user_configs').upsert(updates, {onConflict:'user_id'});
    const tipo = nequiMatch?'Nequi':bancolMatch?'Bancolombia':daviMatch?'Daviplata':'Método de pago';
    const valor = (nequiMatch||bancolMatch||daviMatch||otroMatch)[1].trim();
    await sendWhatsApp(phone, `✅ *${tipo} guardado*\n\n📱 ${valor}\n\n_Escribe "mis datos de pago" para verlos_`);
    return;
  }
  if (lower.startsWith('mi nombre es ') || lower.startsWith('me llamo ')) {
    const name = text.replace(/^(mi nombre es |me llamo )/i, '').trim();
    if (name) { await supabase.from('users').update({ name }).eq('id', user.id); await sendWhatsApp(phone, `Mucho gusto *${name}* 😊`); }
    return;
  }

  // ══════ NAVEGACION DESDE MENU PRINCIPAL ══════
  if (ctx.step === 'menu_principal') {
    const menuMap = {
      '1':'personal','finanzas':'personal','finanzas personales':'personal','mis finanzas':'personal',
      '2':'negocio','negocio':'negocio','mi negocio':'negocio','comerciantes':'negocio',
      '3':'pareja','pareja':'pareja','parejas':'pareja','finanzas pareja':'pareja',
      '4':'viajes','viajes':'viajes','viaje':'viajes',
      '5':'deudas','deudas':'deudas','mis deudas':'deudas',
      '6':'pagos','metodos de pago':'pagos','mis pagos':'pagos','nequi':'pagos','mis llaves':'pagos',
      '7':'mercado','mercado':'mercado','lista mercado':'mercado','mi mercado':'mercado',
      '8':'tareas','tareas':'tareas','mis tareas':'tareas',
      '9':'servicios','servicios':'servicios','mis servicios':'servicios','servicios publicos':'servicios',
      '10':'informes','informes':'informes','informe':'informes','reportes':'informes'
    };
    const dest = menuMap[lower];
    if (dest) {
      await mostrarSubmenu(phone, dest, user);
    } else {
      await sendWhatsApp(phone, `Elige una opcion del *1* al *10* o escribe el nombre del modulo\n\nEscribe *menu* para ver las opciones`);
    }
    return;
  }

  // ══════ SUBMENUS DIRECTOS (sin estar en menu_principal) ══════
  if (/^mercado$|^mi mercado$|^lista mercado$|^lista de mercado$|^mis compras?$/.test(lower)) {
    await mostrarSubmenu(phone, 'mercado', user); return;
  }
  if (/^tareas?$|^mis tareas?$|^pendientes?$|^mis pendientes?$|^lista tareas?$/.test(lower)) {
    await mostrarSubmenu(phone, 'tareas', user); return;
  }
  if (/^servicios?$|^mis servicios?$|^servicios? publicos?$|^vencimientos?$/.test(lower)) {
    await mostrarSubmenu(phone, 'servicios', user); return;
  }
  if (/^modulos?$|^mi modulo$|^modulo actual$|^en que modulo estoy$|^que modulo tengo$/.test(lower)) {
    await mostrarSubmenu(phone, 'modulo', user); return;
  }

  // ══════ NAVEGACION DENTRO DE SUBMENÚ ══════
  if (ctx.step && ctx.step.startsWith('sub_')) {
    const submenuActual = ctx.step.replace('sub_','');
    if (['0','volver','atras','menu','salir','back'].includes(lower)) {
      await clearCtx();
      const planNames = {personal:'👤 Personal',parejas:'💑 Pareja',viajes:'✈️ Viajes',comerciantes:'🏪 Negocio'};
      await sendWhatsApp(phone,
        `🤖 *MiCaja — Menu principal*\n` +
        `Modulo activo: *${planNames[user.plan]}*\n\n` +
        `*1* 💰 Finanzas personales\n` +
        `*2* 🏪 Mi negocio\n` +
        `*3* 💑 Pareja\n` +
        `*4* ✈️ Viajes\n` +
        `*5* 💸 Deudas\n` +
        `*6* 💳 Metodos de pago\n` +
        `*7* 🛒 Lista de mercado\n` +
        `*8* ✅ Tareas\n` +
        `*9* 🔔 Servicios y pagos\n` +
        `*10* 📊 Informes\n\n` +
        `Escribe el numero o el nombre del modulo`
      );
      await setCtx({ step: 'menu_principal' });
      return;
    }
    await manejarSubmenu(phone, submenuActual, lower, user, ctx);
    return;
  }

  // ══════ INFORME / PDF ══════
  if (['informe','pdf','reporte','informe del mes','mi informe','ver informe'].includes(lower) || /informe\s*(del\s*)?(mes|semana|año|ano|todo)/i.test(lower)) {
    const module = user.plan || 'personal';
    const planNames = {personal:'Finanzas Personales',parejas:'Finanzas en Pareja',viajes:'Viajes',comerciantes:'Mi Negocio'};
    const { data: movs } = await supabase.from('movements').select('*').eq('user_id', user.id).eq('module', module).order('date',{ascending:false});
    const inc = (movs||[]).filter(m=>m.type==='income').reduce((s,m)=>s+Number(m.amount),0);
    const exp = (movs||[]).filter(m=>m.type==='expense').reduce((s,m)=>s+Number(m.amount),0);
    const bal = inc - exp;
    const byCat = {};
    (movs||[]).filter(m=>m.type==='expense').forEach(m=>{byCat[m.category]=(byCat[m.category]||0)+Number(m.amount);});
    const topCats = Object.entries(byCat).sort((a,b)=>b[1]-a[1]).slice(0,5).map(([c,v])=>`  • ${c}: $${v.toLocaleString()}`).join('\n');
    try {
      const fecha = new Date().toLocaleDateString('es-CO',{day:'2-digit',month:'long',year:'numeric'});
      const html = generarHTMLInforme(movs||[], planNames[module], fecha, user.name);
      const token = crypto.randomBytes(16).toString('hex');
      await supabase.from('temp_files').insert({token, content: html, filename:`informe-${module}.html`, expires_at: new Date(Date.now()+24*60*60*1000).toISOString()});
      const link = `https://micaja-backend-production.up.railway.app/api/download/${token}`;
      await sendWhatsApp(phone,
        `📄 *Informe ${planNames[module]}*\n` +
        `━━━━━━━━━━━━━━\n` +
        `💵 Ingresos: *$${inc.toLocaleString()}*\n` +
        `💸 Gastos: *$${exp.toLocaleString()}*\n` +
        `${bal>=0?'✅':'⚠️'} Balance: *${bal>=0?'+':''}$${bal.toLocaleString()}*\n` +
        `━━━━━━━━━━━━━━\n` +
        (topCats?`📂 *Top gastos:*\n${topCats}\n━━━━━━━━━━━━━━\n`:'')+
        `📥 *Descarga el informe completo:*\n${link}\n` +
        `_Disponible 24 horas_`
      );
    } catch(e) {
      await sendWhatsApp(phone, `📄 *Informe ${planNames[module]}*\n━━━━━━━━━━━━━━\n💵 $${inc.toLocaleString()} ingresos\n💸 $${exp.toLocaleString()} gastos\n${bal>=0?'✅':'⚠️'} $${bal.toLocaleString()} balance\n━━━━━━━━━━━━━━\n${topCats||'Sin movimientos'}\n\n🌐 milkomercios.in/MiCaja/${module}.html`);
    }
    return;
  }

  // ══════ RESUMEN / BALANCE ══════
  if (['resumen','cuánto llevo','cuanto llevo','balance','cómo voy','como voy','estado','saldo'].includes(lower)) {
    const module = user.plan || 'personal';
    const { data: movs } = await supabase.from('movements').select('*').eq('user_id', user.id).eq('module', module);
    const inc = (movs||[]).filter(m => m.type==='income').reduce((s,m) => s+Number(m.amount), 0);
    const exp = (movs||[]).filter(m => m.type==='expense').reduce((s,m) => s+Number(m.amount), 0);
    const bal = inc - exp;
    if (!(movs||[]).length) { await sendWhatsApp(phone, `Aún no tienes movimientos 📭\n\nEscribe _"pagué luz 80mil"_ para empezar.`); return; }
    const byCat = {};
    (movs||[]).filter(m => m.type==='expense').forEach(m => { byCat[m.category] = (byCat[m.category]||0) + Number(m.amount); });
    const topCats = Object.entries(byCat).sort((a,b) => b[1]-a[1]).slice(0,3).map(([cat,amt]) => `  • ${cat}: $${amt.toLocaleString()}`).join('\n');
    const last3 = (movs||[]).sort((a,b) => new Date(b.created_at)-new Date(a.created_at)).slice(0,3).map(m => `  ${m.type==='income'?'💵':'💸'} ${m.description}: $${Number(m.amount).toLocaleString()}`).join('\n');
    await sendWhatsApp(phone, `📊 *Resumen de ${user.name||'tu cuenta'}*\n\n💵 Ingresos: *$${inc.toLocaleString()}*\n💸 Gastos: *$${exp.toLocaleString()}*\n${bal>=0?'✅':'⚠️'} Balance: *$${bal.toLocaleString()}*\n📋 ${(movs||[]).length} movimientos\n\n${topCats?`📂 *Top gastos:*\n${topCats}\n\n`:''}🕐 *Recientes:*\n${last3}\n\n${inc>0?`Ahorrando el *${Math.round((bal/inc)*100)}%* 👏`:''}`);
    return;
  }

  // ══════ DEUDAS RÁPIDAS ══════
  if (['mis deudas','deudas','qué debo','que debo','cuánto debo','cuanto debo','me deben'].includes(lower)) {
    try {
      const { data: debts } = await supabase.from('debts').select('*').eq('user_id', user.id).eq('status', 'pending').or('status.eq.partial');
      const debo = (debts||[]).filter(d => d.type==='debo');
      const meDeben = (debts||[]).filter(d => d.type==='me_deben');
      const totalDebo = debo.reduce((s,d) => s+Number(d.amount)-Number(d.paid||0), 0);
      const totalMeDeben = meDeben.reduce((s,d) => s+Number(d.amount)-Number(d.paid||0), 0);
      let msg = `🤝 *Mis Deudas*\n\n💸 Yo debo: *$${totalDebo.toLocaleString()}*\n💵 Me deben: *$${totalMeDeben.toLocaleString()}*\n⚖️ Balance: *${totalMeDeben-totalDebo>=0?'+':''}$${(totalMeDeben-totalDebo).toLocaleString()}*\n\n`;
      if (debo.length) { msg += `📋 *Lo que debo:*\n`; debo.slice(0,5).forEach(d => { msg += `  • ${d.person_name}: $${(Number(d.amount)-Number(d.paid||0)).toLocaleString()}\n`; }); }
      if (meDeben.length) { msg += `\n📋 *Lo que me deben:*\n`; meDeben.slice(0,5).forEach(d => { msg += `  • ${d.person_name}: $${(Number(d.amount)-Number(d.paid||0)).toLocaleString()}\n`; }); }
      msg += `\n🌐 milkomercios.in/MiCaja/deudas.html`;
      await sendWhatsApp(phone, msg);
    } catch(e) { await sendWhatsApp(phone, `🌐 Ver deudas: milkomercios.in/MiCaja/deudas.html`); }
    return;
  }

  // ══════ REGISTRAR DEUDAS RÁPIDAS ══════
  const deboMatch = lower.match(/(?:le debo|debo)\s+(\d+[\d.,]*\s*(?:mil|k|m)?)\s+(?:a|le a)?\s*(.+)/i);
  const meDebenMatch = lower.match(/(.+)\s+me debe\s+(\d+[\d.,]*\s*(?:mil|k|m)?)/i);
  if (deboMatch) {
    const amountRaw = deboMatch[1]; const persona = deboMatch[2].trim();
    const amount = parseFloat(amountRaw.replace(/mil|k/i,'').replace(/[.,]/g,'')) * (amountRaw.match(/mil|k/i) ? 1000 : 1);
    await supabase.from('debts').insert({ user_id: user.id, type: 'debo', person_name: persona, amount, status: 'pending', paid: 0 });
    await sendWhatsApp(phone, `💸 Le debes *$${amount.toLocaleString()}* a *${persona}*\n\nEscribe _"mis deudas"_ para ver el resumen.`);
    return;
  }
  if (meDebenMatch) {
    const persona = meDebenMatch[1].trim(); const amountRaw = meDebenMatch[2];
    const amount = parseFloat(amountRaw.replace(/mil|k/i,'').replace(/[.,]/g,'')) * (amountRaw.match(/mil|k/i) ? 1000 : 1);
    await supabase.from('debts').insert({ user_id: user.id, type: 'me_deben', person_name: persona, amount, status: 'pending', paid: 0 });
    await sendWhatsApp(phone, `💵 *${persona}* te debe *$${amount.toLocaleString()}*\n\nEscribe _"mis deudas"_ para ver el resumen.`);
    return;
  }

  // ══════ LINK WEB ══════
  const webCmds = ['web','link','portal','dashboard','login','entrar','ingresar','acceder','mi cuenta','acceso web','entrar a la web'];
  if (webCmds.includes(lower) || webCmds.some(c => lower.includes(c))) {
    try {
      const magicToken = crypto.randomBytes(20).toString('hex');
      const expiresAt = Date.now() + 10 * 60 * 1000;
      await supabase.from('users').update({
        magic_token: magicToken,
        magic_token_expiry: expiresAt
      }).eq('id', user.id);
      const link = `https://milkomercios.in/MiCaja/login.html?magic=${magicToken}`;
      await sendWhatsApp(phone,
        `🔐 *Tu acceso directo a MiCaja:*\n\n` +
        `👉 ${link}\n\n` +
        `⏱ _Este link expira en 10 minutos y es de un solo uso._\n` +
        `_Nadie más puede usarlo — es solo tuyo._`
      );
    } catch(e) {
      await sendWhatsApp(phone, `🌐 milkomercios.in/MiCaja/login.html\n\n📱 ${phone}\n🔐 PIN: ${user.pin}`);
    }
    return;
  }

  // ══════ PAGAR SUSCRIPCIÓN ══════
  if (['pagar','suscripción','suscripcion','renovar','activar'].includes(lower)) {
    try {
      const linkRes = await axios.get(`https://micaja-backend-production.up.railway.app/api/payments/link/${phone}`);
      if (linkRes.data.ok) await sendWhatsApp(phone, `💳 *Suscripción MiCaja — $20.000 COP/mes*\n\n👇 Paga aquí:\n${linkRes.data.url}\n\n⏱ _El link expira en 30 minutos_`);
    } catch(e) { await sendWhatsApp(phone, `💳 Pagar: milkomercios.in/MiCaja/dashboard.html`); }
    return;
  }

  // ══════ BORRAR ÚLTIMO ══════
  if (['borrar último','borrar ultimo','borrar','deshacer'].includes(lower)) {
    const { data: last } = await supabase.from('movements').select('id,description,amount,type,category').eq('user_id', user.id).eq('module', user.plan).order('created_at',{ascending:false}).limit(1).single();
    if (last) {
      await supabase.from('movements').delete().eq('id', last.id);
      await sendWhatsApp(phone, `🗑 Borré: ${last.type==='income'?'💵':'💸'} *${last.description}* — $${Number(last.amount).toLocaleString()}`);
    } else { await sendWhatsApp(phone, `No tienes movimientos para borrar 📭`); }
    return;
  }

  // ══════ VER ÚLTIMOS MOVIMIENTOS ══════
  if (['últimos','ultimos','mis movimientos','ver movimientos'].includes(lower)) {
    const { data: movs } = await supabase.from('movements').select('*').eq('user_id', user.id).eq('module', user.plan).order('created_at',{ascending:false}).limit(5);
    if (!movs || !movs.length) { await sendWhatsApp(phone, `No tienes movimientos aún 📭`); return; }
    const lista = movs.map((m,i) => `${i+1}. ${m.type==='income'?'💵':'💸'} ${m.description} — $${Number(m.amount).toLocaleString()}\n   📂 ${m.category} · ${m.date}`).join('\n\n');
    await sendWhatsApp(phone, `🕐 *Últimos 5 movimientos:*\n\n${lista}`);
    return;
  }

  // ══════ CONFIRMACIÓN DE CATEGORÍA ══════
  if (ctx.step === 'confirm_cat') {
    const cats = {
      '1':'Alimentación','2':'Arriendo','3':'Servicios','4':'Transporte',
      '5':'Salud','6':'Entretenimiento','7':'Educación','8':'Nómina',
      '9':'Proveedores','10':'Créditos','11':'Ventas','12':'Otros'
    };
    if (lower === 'cancelar' || lower === 'no' || lower === 'cancel') {
      await clearCtx();
      await sendWhatsApp(phone, `❌ Cancelado. No se guardó nada.\n\nCuando quieras escríbeme de nuevo 😊`);
      return;
    }
    const useCat = cats[lower] ||
      (Object.values(cats).find(c => c.toLowerCase() === lower)) ||
      (['si','sí','ok','listo','dale','correcto','exacto','eso','así','asi','guardalo','guardar'].includes(lower) ? ctx.category : null);
    if (useCat) {
      const { error } = await supabase.from('movements').insert({
        user_id: user.id, type: ctx.type, amount: ctx.amount,
        description: ctx.description, category: useCat,
        source: 'whatsapp', module: user.plan
      }).select().single();
      if (!error) {
        await clearCtx();
        const { data: movs } = await supabase.from('movements').select('type, amount')
          .eq('user_id', user.id).eq('module', user.plan);
        const bal = (movs||[]).reduce((s,m) => s + (m.type==='income' ? Number(m.amount) : -Number(m.amount)), 0);
        const signo = ctx.type === 'income' ? '+' : '-';
        const emoji = ctx.type === 'income' ? '💵' : '💸';
        await sendWhatsApp(phone,
          `✅ *${ctx.type==='income'?'Ingreso':'Gasto'} guardado*\n\n` +
          `${emoji} ${ctx.description}\n` +
          `💰 ${signo}$${Number(ctx.amount).toLocaleString()} COP\n` +
          `📂 ${useCat}\n\n` +
          `Balance actual: *${bal>=0?'+':''}$${bal.toLocaleString()}* ${bal<0?'⚠️':'👍'}\n\n` +
          `_Escribe "cómo voy" para ver tu resumen_`
        );
      } else {
        await clearCtx();
        await sendWhatsApp(phone, `❌ Error al guardar. Intenta de nuevo.`);
      }
    } else {
      await sendWhatsApp(phone,
        `Responde con el número de la categoría:\n\n` +
        `*1* Alimentación · *2* Arriendo · *3* Servicios\n` +
        `*4* Transporte · *5* Salud · *6* Entretenimiento\n` +
        `*7* Educación · *8* Nómina · *9* Proveedores\n` +
        `*10* Créditos · *11* Ventas · *12* Otros\n\n` +
        `O escribe *sí* para guardar con categoría _${ctx.category}_\n` +
        `O escribe *no* para cancelar`
      );
    }
    return;
  }

  // ══════ PARSER IA ══════
  const parsed = await parseWithAI(lower, user.name, user.plan);
  if (parsed) {
    const planNames = {personal:'👤 Personal',parejas:'💑 Pareja',viajes:'✈️ Viajes',comerciantes:'🏪 Negocio'};
    const emoji = parsed.type === 'income' ? '💵' : '💸';
    const signo = parsed.type === 'income' ? '+' : '-';
    await setCtx({step:'confirm_cat', type:parsed.type, amount:parsed.amount, description:parsed.description, category:parsed.category});
    await sendWhatsApp(phone,
      `${emoji} *¿Confirmas este ${parsed.type==='income'?'ingreso':'gasto'}?*\n\n` +
      `📝 *${parsed.description}*\n` +
      `💰 ${signo}$${Number(parsed.amount).toLocaleString()} COP\n` +
      `📂 Categoría: *${parsed.category}*\n` +
      `📋 Módulo: *${planNames[user.plan]}*\n\n` +
      `✅ *sí* — guardar así\n` +
      `🔢 *1-12* — cambiar categoría\n` +
      `❌ *no* — cancelar\n\n` +
      `_Categorías: 1.Alimentación 2.Arriendo 3.Servicios 4.Transporte 5.Salud 6.Entretenimiento 7.Educación 8.Nómina 9.Proveedores 10.Créditos 11.Ventas 12.Otros_`
    );
    return;
  }

  await sendWhatsApp(phone, `Mmm, no entendí bien 🤔\n\nPrueba así:\n💸 _"pagué arriendo 800mil"_\n💵 _"me cayó el sueldo 2 millones"_\n💵 _"vendí mercancía 500k"_\n\nO escribe *menu* para ver todo 😊`);
}

// ══════ BUSCAR USUARIO ══════
app.get('/api/user/phone/:phone', async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('id, name, phone, plan, role, status, created_at').eq('phone', req.params.phone).single();
    if (!user) return res.status(404).json({ error: 'No encontrado' });
    res.json({ ok: true, user });
  } catch (err) { res.status(500).json({ error: 'Error' }); }
});

// ══════ PARSER CON IA ══════
async function parseWithAI(text, userName, plan) {
  try {
    const ANTHROPIC_KEY = process.env.ANTHROPIC_KEY;
    if (!ANTHROPIC_KEY) return parseFinancialMessage(text);
    const res = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-haiku-4-5-20251001', max_tokens: 300,
      messages: [{ role: 'user', content: `Eres el asistente financiero de MiCaja para Colombia. Usuario: ${userName||'usuario'}, módulo: ${plan||'personal'}.

Analiza este mensaje en español colombiano y extrae la información financiera. Responde SOLO con JSON válido sin markdown ni explicaciones:
{"type":"income"|"expense"|"unknown","amount":number_in_COP,"description":"descripcion_limpia","category":"categoria"}

PALABRAS QUE INDICAN INGRESO: vendí, vendi, cobré, cobre, cobrar, me pagaron, me cayó, me cayeron, recibí, recibi, me entraron, entraron, ingresaron, me ingresaron, depositaron, me depositaron, abonaron, me abonaron, llegó, llegaron, gané, gane, salario, sueldo, quincena, pago mensual, me transfirieron, me consignaron, consignaron, recolecté, recolecte, facturé, facture, contrato, honorarios, comisión, comision, venta, vendimos, vendieron, cliente pagó, cliente pago, recaudo, recaudé, recaude, cayó plata, cayeron billetes, entró el pago, entro el pago, me entró, me entro, me llegó, me llego, cobro, me hicieron el pago, realizaron el pago.

PALABRAS QUE INDICAN GASTO: pagué, pague, gasté, gaste, compré, compre, cancelé, cancele, abono, cuota, factura, me cobró, me cobro, debité, debite, salió, salio, se fue, tuve que pagar, me tocó pagar, me toco pagar, erogué, erogue, desembolsé, desembolse, invertí, inverta, consumí, consumi, comí, comi, fui al, fui a, almorcé, almorce, cené, cene, tomé, tome, me gasté, me gaste, me costó, me costo, hubo que pagar, pagamos, compramos.

MONTOS: "mil"=1000, "k"=1000, "millón"/"millon"/"millones"=1000000, "pesos"=1, "luca"=1000, "lucas"=1000, "mega"=1000000, "palo"=1000000, "palos"=1000000, "billete"=1000, "billetes"=1000. Ejemplos: "80k"=80000, "1.5 millones"=1500000, "dos lucras"=2000, "medio palo"=500000, "2 palos"=2000000.

Categorías gastos: Alimentación, Arriendo, Servicios, Transporte, Salud, Entretenimiento, Educación, Nómina, Proveedores, Mercancía, Otros
Categorías ingresos: Ventas, Salario, Freelance, Cobros, Otros ingresos

Si no hay monto claro, type="unknown". Description debe ser limpia y corta (máx 5 palabras).

Mensaje: "${text}"` }]
    }, { headers: { 'x-api-key': ANTHROPIC_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' } });
    const raw = res.data.content[0].text.trim().replace(/```json|```/g,'').trim();
    const parsed = JSON.parse(raw);
    if (parsed.type === 'unknown' || !parsed.amount) return null;
    return parsed;
  } catch (e) { return parseFinancialMessage(text); }
}

// ══════ PARSER SIMPLE (fallback sin IA) ══════
function parseFinancialMessage(text) {
  let n = text
    .replace(/(\d+[\d.,]*)\s*mil(?:es)?/gi, (_,x) => String(parseFloat(x.replace(/[,.]/g,''))*1000))
    .replace(/(\d+[\d.,]*)\s*(?:millones?|palos?|megas?)/gi, (_,x) => String(parseFloat(x.replace(/[,.]/g,''))*1000000))
    .replace(/(\d+[\d.,]*)\s*k\b/gi, (_,x) => String(parseFloat(x.replace(/[,.]/g,''))*1000))
    .replace(/(?:un|una|medio)\s*(?:palo|mega|millón|millon)/gi, (m) => /medio/i.test(m)?'500000':'1000000')
    .replace(/(?:lucra|luca)s?\b/gi, '000')
    .replace(/billete[s]?\b/gi, '000');

  const amtMatch = n.match(/\$?\s*([\d,.]+)/);
  if (!amtMatch) return null;
  const amount = parseFloat(amtMatch[1].replace(/[,.]/g, ''));
  if (!amount || amount <= 0) return null;

  const incWords = [
    'vendí','vendi','cobré','cobre','cobrar','ingreso','me pagaron','recibí','recibi',
    'venta','gané','gane','salario','sueldo','quincena','ingresaron','me ingresaron',
    'entró','entro','llegó','llego','depositaron','me depositaron','abonaron','me abonaron',
    'me cayó','me cayo','cayó plata','me entró','me entro','me llegó','me llego',
    'transfirieron','consignaron','me consignaron','recolecté','recolecte',
    'facturé','facture','honorarios','comisión','comision','recaudo','recaudé','recaude',
    'cliente pagó','cliente pago','realizaron el pago','me hicieron el pago',
    'pago mensual','cobro mensual','contrato','entraron','cayeron'
  ];
  const expWords = [
    'pagué','pague','gasté','gaste','compré','compre','cancelé','cancele',
    'cuota','factura','me cobró','me cobro','debité','debite','salió','salio',
    'se fue','me costó','me costo','erogué','erogue','desembolsé','desembolse',
    'invertí','inverta','comí','comi','almorcé','almorce','cené','cene',
    'fui al','fui a','me gasté','me gaste','hubo que pagar','pagamos','compramos',
    'me tocó pagar','me toco pagar','tuve que pagar'
  ];

  const tl = n.toLowerCase();
  let type = 'expense';
  for (const w of incWords) { if (tl.includes(w)) { type = 'income'; break; } }
  for (const w of expWords) { if (tl.includes(w)) { type = 'expense'; break; } }

  let desc = text
    .replace(/\$?\s*[\d,.]+\s*(?:mil(?:es)?|millones?|palos?|k\b|pesos)?/gi, '')
    .replace(/pagué|pague|gasté|gaste|compré|compre|cancelé|cancele|cuota de|vendí|vendi|cobré|cobre|ingresaron|me ingresaron|me pagaron|recibí|recibi|gané|gane|me cayó|me cayo|depositaron|abonaron|llegó|llego|entró|entro|salió|salio|se fue|me costó|me costo|fui al|fui a/gi, '')
    .replace(/^\s*(de|en|por|el|la|un|una|los|las|del)\s+/i, '')
    .replace(/\s+/g, ' ').trim();

  if (!desc || desc.length < 2) desc = type === 'income' ? 'Ingreso' : 'Gasto';
  desc = desc.charAt(0).toUpperCase() + desc.slice(1);
  return { type, amount, description: desc, category: autoCategory(desc+' '+text, type) };
}

// ══════ AUTO-CATEGORIZACIÓN ══════
function autoCategory(text, type) {
  const d = text.toLowerCase();
  if (type === 'income') {
    if (/venta|vendí|vendi|vender|cliente|producto|mercancía|mercancia/i.test(d)) return 'Ventas';
    if (/salario|sueldo|nómina|nomina|quincena|mensual|empleo|trabajo/i.test(d)) return 'Salario';
    if (/freelance|proyecto|servicio prestado|honorario|consultoría|consultoria/i.test(d)) return 'Freelance';
    if (/cobr|deuda|prestamo|me debían|me debian|abono|pagaron/i.test(d)) return 'Cobros';
    return 'Otros ingresos';
  }
  if (/luz|electricidad|enel|codensa|agua|acueducto|gas natural|surtigas|internet|claro|tigo|etb|movistar|teléfono|telefono|celular|plan celular|wifi|cable|tv|servicio público|servicio publico/i.test(d)) return 'Servicios';
  if (/arriendo|alquiler|renta|arrendamiento|administración|administracion/i.test(d)) return 'Arriendo';
  if (/mercado|supermercado|exito|carulla|olimpica|makro|comida|almuerzo|desayuno|cena|restaurante|comedor|cafetería|cafeteria|domicilio|rappi|ifood|dominos|pizza|pollo|hamburguesa|fritura|arepas|pandebono/i.test(d)) return 'Alimentación';
  if (/uber|taxi|bus|transporte|gasolina|combustible|parqueo|peaje|moto|bicicleta|transmilenio|metro|sitp|parqueadero/i.test(d)) return 'Transporte';
  if (/salud|médico|medico|doctor|farmacia|droguería|drogueria|medicina|clínica|clinica|hospital|cita|examen|laboratorio|eps|seguro médico|seguro medico/i.test(d)) return 'Salud';
  if (/netflix|spotify|prime|disney|cine|película|pelicula|entretenimiento|concierto|evento|bar|rumba|discoteca|juego|videojuego|app|suscripción|suscripcion/i.test(d)) return 'Entretenimiento';
  if (/colegio|universidad|educación|educacion|curso|taller|libro|útiles|utiles|matrícula|matricula|pensión educativa|pension educativa/i.test(d)) return 'Educación';
  if (/nómina|nomina|empleado|trabajador|sueldo empleado|seguridad social|parafiscal|cesantías|cesantias/i.test(d)) return 'Nómina';
  if (/proveedor|mercancía|mercancia|inventario|insumo|materia prima|importación|importacion|compra negocio/i.test(d)) return 'Proveedores';
  if (/cuota casa|cuota carro|cuota moto|cuota crédito|cuota credito|hipoteca|banco|leasing|préstamo|prestamo|crédito|credito|tarjeta|bancolombia|davivienda|bbva|bogotá|bogota/i.test(d)) return 'Créditos';
  if (/ropa|zapatos|calzado|vestido|ropa|almacén|almacen|zapatería|zapateria/i.test(d)) return 'Ropa';
  return 'Otros';
}

// ══════════════════════════════════════
// SISTEMA DE SUBMENÚS NAVEGABLES
// ══════════════════════════════════════
async function mostrarSubmenu(phone, modulo, user) {
  const planNames = {personal:'👤 Personal',parejas:'💑 Pareja',viajes:'✈️ Viajes',comerciantes:'🏪 Negocio'};
  // FIX: usar setCtxByPhone directamente — limpio, sin merge
  await setCtxByPhone(phone, {step:'sub_'+modulo});

  switch(modulo) {
    case 'personal': case 'negocio': case 'pareja': {
      const mod = modulo==='pareja'?'parejas':modulo==='negocio'?'comerciantes':modulo;
      const nombre = {personal:'💰 Finanzas personales',negocio:'🏪 Mi negocio',pareja:'💑 Finanzas pareja'}[modulo];
      const { data: movs } = await supabase.from('movements').select('type,amount').eq('user_id',user.id).eq('module',mod);
      const inc=(movs||[]).filter(m=>m.type==='income').reduce((s,m)=>s+Number(m.amount),0);
      const exp=(movs||[]).filter(m=>m.type==='expense').reduce((s,m)=>s+Number(m.amount),0);
      const bal=inc-exp;
      await sendWhatsApp(phone,
        `${nombre}\n━━━━━━━━━━━━━━\n`+
        `💵 Ingresos: *$${inc.toLocaleString()}*\n`+
        `💸 Gastos: *$${exp.toLocaleString()}*\n`+
        `${bal>=0?'✅':'⚠️'} Balance: *${bal>=0?'+':''}$${bal.toLocaleString()}*\n\n`+
        `Que quieres hacer?\n`+
        `*1* Ver resumen detallado\n`+
        `*2* Registrar gasto\n`+
        `*3* Registrar ingreso\n`+
        `*4* Ver ultimos movimientos\n`+
        `*5* 📄 Descargar informe PDF\n`+
        (modulo!=='personal'?`*6* Cambiar a este modulo\n`:``)+
        `*0* Volver al menu`
      );
      break;
    }
    case 'viajes': {
      const { data: trips } = await supabase.from('trips').select('*').eq('user_id',user.id).order('created_at',{ascending:false}).limit(5);
      const activos=(trips||[]).filter(t=>t.status==='active');
      await sendWhatsApp(phone,
        `✈️ *Viajes*\n━━━━━━━━━━━━━━\n`+
        `Total: *${(trips||[]).length}* | Activos: *${activos.length}*\n`+
        (activos.length?`Activo: *${activos[0].name}*\n`:``)+`\n`+
        `*1* Ver mis viajes\n*2* Ver gastos del viaje activo\n*3* Crear nuevo viaje\n*4* 📄 Informe PDF\n*0* Menu`
      );
      break;
    }
    case 'deudas': {
      const { data: deudas } = await supabase.from('debts').select('*').eq('user_id',user.id).neq('status','paid');
      const meDeben=(deudas||[]).filter(d=>d.type==='me_deben');
      const yoDebo=(deudas||[]).filter(d=>d.type==='debo');
      const totalMD=meDeben.reduce((s,d)=>s+Number(d.amount)-(Number(d.paid)||0),0);
      const totalYD=yoDebo.reduce((s,d)=>s+Number(d.amount)-(Number(d.paid)||0),0);
      await sendWhatsApp(phone,
        `💸 *Deudas*\n━━━━━━━━━━━━━━\n`+
        `💰 Me deben: *$${totalMD.toLocaleString()}* (${meDeben.length})\n`+
        `💳 Yo debo: *$${totalYD.toLocaleString()}* (${yoDebo.length})\n`+
        `${totalMD>=totalYD?'✅':'⚠️'} Balance: *${totalMD>=totalYD?'+':''}$${(totalMD-totalYD).toLocaleString()}*\n\n`+
        `*1* Ver quien me debe\n*2* Ver a quien le debo\n*3* Registrar deuda\n*4* 📄 Informe PDF\n*0* Menu`
      );
      break;
aver
    }
    case 'pagos': {
      const { data: cfg } = await supabase.from('user_configs').select('*').eq('user_id',user.id).single();
      await sendWhatsApp(phone,
        `💳 *Metodos de pago*\n━━━━━━━━━━━━━━\n`+
        `${cfg?.nequi?`📱 Nequi: *${cfg.nequi}*\n`:`📱 Nequi: _no configurado_\n`}`+
        `${cfg?.daviplata?`📱 Daviplata: *${cfg.daviplata}*\n`:``}`+
        `${cfg?.bancolombia?`🏦 Bancolombia: *${cfg.bancolombia}*\n`:`🏦 Bancolombia: _no configurado_\n`}`+
        `${cfg?.otro_pago?`💰 Otro: *${cfg.otro_pago}*\n`:``}\n`+
        `*1* Ver mis datos\n*2* Guardar Nequi\n*3* Guardar Bancolombia\n*4* Guardar Daviplata\n*0* Menu`
      );
      break;
    }
    case 'mercado': {
      const { data: items } = await supabase.from('mercado').select('*').eq('user_id',user.id).eq('done',false).order('created_at',{ascending:false});
      const total=(items||[]).length;
      const porCat={};
      (items||[]).forEach(i=>{const c=i.categoria||'Otros';porCat[c]=(porCat[c]||[]).concat(i);});
      let lista='';
      Object.keys(porCat).slice(0,3).forEach(cat=>{lista+=`\n*${cat}:*\n`;porCat[cat].slice(0,4).forEach(i=>{lista+=`  ☐ ${i.nombre}${i.cantidad?' ('+i.cantidad+')':''}\n`;});});
      if(total>12) lista+=`\n_...y ${total-12} mas_`;
      await sendWhatsApp(phone,
        `🛒 *Lista de mercado (${total})*\n━━━━━━━━━━━━━━`+
        (lista||'\n🎉 Lista vacia!')+`\n\n`+
        `*1* Ver lista completa\n*2* Agregar producto\n*0* Menu`
      );
      break;
    }
    case 'tareas': {
      const { data: tareas } = await supabase.from('tasks').select('*').eq('user_id',user.id).eq('done',false).order('created_at',{ascending:false});
      const total=(tareas||[]).length;
      const alta=(tareas||[]).filter(t=>t.prioridad==='alta').length;
      const priIcon={alta:'🔴',media:'🟡',baja:'🔵'};
      let lista=(tareas||[]).slice(0,6).map(t=>`${priIcon[t.prioridad]||'⚪'} ${t.titulo}${t.fecha?' ('+t.fecha+')':''}`).join('\n');
      if(total>6) lista+=`\n_...y ${total-6} mas_`;
      await sendWhatsApp(phone,
        `✅ *Tareas pendientes (${total})*\n━━━━━━━━━━━━━━\n`+
        `Alta prioridad: *${alta}*\n\n`+
        (lista||'🎉 Sin tareas pendientes!')+`\n\n`+
        `*1* Ver todas\n*2* Agregar tarea\n*0* Menu`
      );
      break;
    }
    case 'servicios': {
      const { data: servs } = await supabase.from('servicios').select('*').eq('user_id',user.id).order('dia');
      const diaHoy=new Date().getDate();
      const vencidos=(servs||[]).filter(s=>!s.pagado_mes&&s.dia<diaHoy);
      const proximos=(servs||[]).filter(s=>!s.pagado_mes&&s.dia>=diaHoy&&s.dia-diaHoy<=5);
      const pagados=(servs||[]).filter(s=>s.pagado_mes);
      let lista='';
      if(vencidos.length) lista+=`\n⚠️ *Vencidos:*\n`+vencidos.map(s=>`  ${s.icono} ${s.nombre}`).join('\n');
      if(proximos.length) lista+=`\n📅 *Proximos:*\n`+proximos.map(s=>`  ${s.icono} ${s.nombre} — dia ${s.dia}`).join('\n');
      if(pagados.length) lista+=`\n✅ *Pagados:*\n`+pagados.map(s=>`  ${s.icono} ${s.nombre}`).join('\n');
      await sendWhatsApp(phone,
        `🔔 *Servicios (${(servs||[]).length})*\n━━━━━━━━━━━━━━\n`+
        `⚠️ Vencidos: *${vencidos.length}* | 📅 Proximos: *${proximos.length}*`+
        (lista||'\n🎉 Todo al dia!')+`\n\n`+
        `*1* Ver todos\n*2* Marcar como pagado\n*0* Menu`
      );
      break;
    }
    case 'informes': {
      await sendWhatsApp(phone,
        `📊 *Informes*\n━━━━━━━━━━━━━━\n`+
        `*1* 📄 Mes actual\n`+
        `*2* 📄 Historico completo\n`+
        `*3* 📄 Finanzas personales\n`+
        `*4* 📄 Mi negocio\n`+
        `*5* 📄 Finanzas en pareja\n`+
        `*0* Menu`
      );
      break;
    }
    case 'modulo': {
      const actual=planNames[user.plan]||'👤 Personal';
      await sendWhatsApp(phone,
        `📋 *Modulo activo: ${actual}*\n━━━━━━━━━━━━━━\n\n`+
        `*1* 👤 Personal\n*2* 🏪 Negocio\n*3* 💑 Pareja\n*4* ✈️ Viajes\n\n*0* Menu`
      );
      break;
    }
  }
}

async function manejarSubmenu(phone, modulo, lower, user, ctx) {
  const planNames = {personal:'👤 Personal',parejas:'💑 Pareja',viajes:'✈️ Viajes',comerciantes:'🏪 Negocio'};
  // helper para acceder al text original desde el contexto de llamada
  // lower ya viene normalizado, text original lo reconstruimos para insertar
  const text = lower; // para insertar en DB, usamos lower (ya es texto limpio)

  async function generarPDFModulo(mod, titulo) {
    const modKey=mod==='pareja'?'parejas':mod==='negocio'?'comerciantes':mod;
    const {data}=await supabase.from('movements').select('*').eq('user_id',user.id).eq('module',modKey).order('date',{ascending:false});
    const movs=data||[];
    const fecha=new Date().toLocaleDateString('es-CO',{day:'2-digit',month:'long',year:'numeric'});
    const html=generarHTMLInforme(movs,titulo,fecha,user.name);
    const token=crypto.randomBytes(16).toString('hex');
    await supabase.from('temp_files').insert({token,content:html,filename:`informe-${mod}.html`,expires_at:new Date(Date.now()+24*60*60*1000).toISOString()});
    return `https://micaja-backend-production.up.railway.app/api/download/${token}`;
  }

  switch(modulo) {
    case 'personal': case 'negocio': case 'pareja': {
      const mod=modulo==='pareja'?'parejas':modulo==='negocio'?'comerciantes':modulo;
      const titulo={personal:'Finanzas Personales',negocio:'Mi Negocio',pareja:'Finanzas en Pareja'}[modulo];
      if(lower==='1'){
        const {data:movs}=await supabase.from('movements').select('*').eq('user_id',user.id).eq('module',mod).order('date',{ascending:false});
        const inc=(movs||[]).filter(m=>m.type==='income').reduce((s,m)=>s+Number(m.amount),0);
        const exp=(movs||[]).filter(m=>m.type==='expense').reduce((s,m)=>s+Number(m.amount),0);
        const byCat={};
        (movs||[]).filter(m=>m.type==='expense').forEach(m=>{byCat[m.category]=(byCat[m.category]||0)+Number(m.amount);});
        const topCats=Object.entries(byCat).sort((a,b)=>b[1]-a[1]).slice(0,5).map(([c,v])=>`  • ${c}: $${v.toLocaleString()}`).join('\n');
        await sendWhatsApp(phone,`📊 *${titulo}*\n━━━━━━━━━━━━━━\n💵 $${inc.toLocaleString()} ingresos\n💸 $${exp.toLocaleString()} gastos\n${(inc-exp)>=0?'✅':'⚠️'} $${(inc-exp).toLocaleString()} balance\n📋 ${(movs||[]).length} movimientos\n━━━━━━━━━━━━━━\n${topCats?`📂 Top gastos:\n${topCats}\n`:''}\n*5* PDF | *0* Menu`);
      } else if(lower==='2'){
        await setCtxByPhone(phone,{step:`sub_${modulo}`,esperando:'gasto',modulo:mod});
        await sendWhatsApp(phone,`💸 Escribe el gasto:\n_"pague mercado 150mil"_\n\n*0* Cancelar`);
      } else if(lower==='3'){
        await setCtxByPhone(phone,{step:`sub_${modulo}`,esperando:'ingreso',modulo:mod});
        await sendWhatsApp(phone,`💵 Escribe el ingreso:\n_"me ingresaron 2 millones"_\n\n*0* Cancelar`);
      } else if(lower==='4'){
        const {data:movs}=await supabase.from('movements').select('*').eq('user_id',user.id).eq('module',mod).order('date',{ascending:false}).limit(8);
        const lista=(movs||[]).map(m=>`${m.type==='income'?'💵':'💸'} ${m.description} $${Number(m.amount).toLocaleString()} (${m.date})`).join('\n');
        await sendWhatsApp(phone,`🕐 *Ultimos movimientos*\n━━━━━━━━━━━━━━\n${lista||'Sin movimientos'}\n\n*5* PDF | *0* Menu`);
      } else if(lower==='5'){
        try{ const link=await generarPDFModulo(modulo,titulo); await sendWhatsApp(phone,`📄 *${titulo}*\n\n📥 ${link}\n_24 horas_\n\n*0* Menu`); }
        catch(e){ await sendWhatsApp(phone,`Error generando PDF.\n\n*0* Menu`); }
      } else if(lower==='6'&&modulo!=='personal'){
        await supabase.from('users').update({plan:mod}).eq('id',user.id);
        await setCtxByPhone(phone,{});
        await sendWhatsApp(phone,`✅ Modulo: *${planNames[mod]}* 💪\n\nEscribe *menu*`);
      } else if(ctx.esperando==='gasto'||ctx.esperando==='ingreso'){
        const parsed=await parseWithAI(lower,user.name,ctx.modulo||user.plan);
        if(parsed){
          const modTarget=ctx.modulo||user.plan;
          await setCtxByPhone(phone,{step:`sub_${modulo}`,step2:'confirm_submenu',type:parsed.type,amount:parsed.amount,description:parsed.description,category:parsed.category,modulo:modTarget});
          await sendWhatsApp(phone,`${parsed.type==='income'?'💵':'💸'} *${parsed.description}*\n$${Number(parsed.amount).toLocaleString()} COP — ${parsed.category}\n\n*si* guardar | *no* cancelar`);
        } else { await sendWhatsApp(phone,`No entendi. Escribe el movimiento de nuevo.\n_"pague mercado 50mil"_\n\n*0* Menu`); }
      } else if(ctx.step2==='confirm_submenu'){
        if(['si','sí','ok','dale','listo'].includes(lower)){
          await supabase.from('movements').insert({user_id:user.id,type:ctx.type,amount:ctx.amount,description:ctx.description,category:ctx.category,source:'whatsapp',module:ctx.modulo||user.plan});
          await setCtxByPhone(phone,{step:`sub_${modulo}`});
          await sendWhatsApp(phone,`✅ Guardado!\n\n*1* Resumen | *5* PDF | *0* Menu`);
        } else {
          await setCtxByPhone(phone,{step:`sub_${modulo}`});
          await sendWhatsApp(phone,`❌ Cancelado.\n\n*0* Menu`);
        }
      } else { await mostrarSubmenu(phone,modulo,user); }
      break;
    }
    case 'deudas': {
      if(lower==='1'){
        const {data:d}=await supabase.from('debts').select('*').eq('user_id',user.id).neq('status','paid').eq('type','me_deben');
        if(!d||!d.length){await sendWhatsApp(phone,`Nadie te debe! 🎉\n\n*0* Menu`);return;}
        await sendWhatsApp(phone,`💰 *Me deben:*\n`+d.map(x=>{const p=Number(x.amount)-(Number(x.paid)||0);return `👤 *${x.person_name}*: $${p.toLocaleString()}${x.description?' — '+x.description:''}`;}).join('\n')+`\n\n*4* PDF | *0* Menu`);
      } else if(lower==='2'){
        const {data:d}=await supabase.from('debts').select('*').eq('user_id',user.id).neq('status','paid').eq('type','debo');
        if(!d||!d.length){await sendWhatsApp(phone,`No debes nada! 🎉\n\n*0* Menu`);return;}
        await sendWhatsApp(phone,`💳 *Yo debo:*\n`+d.map(x=>{const p=Number(x.amount)-(Number(x.paid)||0);return `👤 *${x.person_name}*: $${p.toLocaleString()}${x.description?' — '+x.description:''}`;}).join('\n')+`\n\n*4* PDF | *0* Menu`);
      } else if(lower==='3'){
        await setCtxByPhone(phone,{step:'sub_deudas',esperando:'nueva_deuda'});
        await sendWhatsApp(phone,`Registra la deuda:\n_"le debo 200k a Juan"_\n_"Pedro me debe 500mil"_\n\n*0* Cancelar`);
      } else if(lower==='4'){
        try{
          const {data:deudas}=await supabase.from('debts').select('*').eq('user_id',user.id).neq('status','paid');
          const meDeben=(deudas||[]).filter(d=>d.type==='me_deben');
          const yoDebo=(deudas||[]).filter(d=>d.type==='debo');
          const totalMD=meDeben.reduce((s,d)=>s+Number(d.amount)-(Number(d.paid)||0),0);
          const totalYD=yoDebo.reduce((s,d)=>s+Number(d.amount)-(Number(d.paid)||0),0);
          const html=`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Deudas</title><style>body{font-family:Segoe UI,sans-serif;padding:28px;color:#0F172A}h1{font-size:20px;font-weight:800;margin-bottom:3px}.sub{color:#64748B;font-size:12px;margin-bottom:18px}.cards{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:18px}.card{border-radius:10px;padding:14px;text-align:center}.val{font-size:18px;font-weight:800;margin:4px 0}.lbl{font-size:11px;color:#64748B}.sec h3{font-size:13px;font-weight:700;margin:14px 0 8px;border-bottom:2px solid #E2E8F0;padding-bottom:4px}.row{display:flex;gap:8px;padding:5px 0;border-bottom:1px solid #F8FAFC;font-size:11px}.footer{margin-top:20px;font-size:10px;color:#94A3B8;text-align:center;border-top:1px solid #E2E8F0;padding-top:10px}</style></head><body><h1>Deudas</h1><div class="sub">${new Date().toLocaleDateString('es-CO',{day:'2-digit',month:'long',year:'numeric'})} — ${user.name||''}</div><div class="cards"><div class="card" style="background:#ECFDF5;border:1px solid #6EE7B7"><div class="val" style="color:#059669">$${totalMD.toLocaleString()}</div><div class="lbl">Me deben</div></div><div class="card" style="background:#FEF2F2;border:1px solid #FCA5A5"><div class="val" style="color:#EF4444">$${totalYD.toLocaleString()}</div><div class="lbl">Yo debo</div></div><div class="card" style="background:${totalMD>=totalYD?'#EFF6FF':'#FEF2F2'};border:1px solid ${totalMD>=totalYD?'#93C5FD':'#FCA5A5'}"><div class="val" style="color:${totalMD>=totalYD?'#2563EB':'#EF4444'}">${totalMD>=totalYD?'+':''}$${(totalMD-totalYD).toLocaleString()}</div><div class="lbl">Balance</div></div></div><div class="sec"><h3>Me deben</h3>${meDeben.map(d=>{const p=Number(d.amount)-(Number(d.paid)||0);return `<div class="row"><span style="flex:1;font-weight:600">${d.person_name}</span><span style="color:#64748B">${d.description||''}</span><span style="font-weight:700;color:#059669">$${p.toLocaleString()}</span></div>`;}).join('')}</div><div class="sec"><h3>Yo debo</h3>${yoDebo.map(d=>{const p=Number(d.amount)-(Number(d.paid)||0);return `<div class="row"><span style="flex:1;font-weight:600">${d.person_name}</span><span style="color:#64748B">${d.description||''}</span><span style="font-weight:700;color:#EF4444">$${p.toLocaleString()}</span></div>`;}).join('')}</div><div class="footer">MiCaja — milkomercios.in/MiCaja</div></body></html>`;
          const token=crypto.randomBytes(16).toString('hex');
          await supabase.from('temp_files').insert({token,content:html,filename:'deudas.html',expires_at:new Date(Date.now()+24*60*60*1000).toISOString()});
          await sendWhatsApp(phone,`📄 *Informe Deudas*\n\n📥 https://micaja-backend-production.up.railway.app/api/download/${token}\n_24 horas_\n\n*0* Menu`);
        }catch(e){await sendWhatsApp(phone,`Error generando PDF.\n\n*0* Menu`);}
      } else { await mostrarSubmenu(phone,'deudas',user); }
      break;
    }
    case 'pagos': {
      if(lower==='1'){
        const {data:cfg}=await supabase.from('user_configs').select('*').eq('user_id',user.id).single();
        await sendWhatsApp(phone,`💳 *Datos de pago*\n━━━━━━━━━━━━━━\n`+(cfg?.nequi?`📱 Nequi: *${cfg.nequi}*\n`:`📱 Nequi: _no guardado_\n`)+(cfg?.daviplata?`📱 Daviplata: *${cfg.daviplata}*\n`:``)+( cfg?.bancolombia?`🏦 Bancolombia: *${cfg.bancolombia}*\n`:`🏦 Bancolombia: _no guardado_\n`)+(cfg?.otro_pago?`💰 Otro: *${cfg.otro_pago}*\n`:``)+`\n*0* Menu`);
      } else if(['2','3','4'].includes(lower)){
        const tipo={'2':'nequi','3':'bancol','4':'daviplata'}[lower];
        const nombre={'2':'Nequi','3':'Bancolombia','4':'Daviplata'}[lower];
        await setCtxByPhone(phone,{step:'sub_pagos',esperando:tipo});
        await sendWhatsApp(phone,`Escribe tu numero de ${nombre}:\n_Ej: 3001234567_\n\n*0* Cancelar`);
      } else if(ctx.esperando){
        const updates={user_id:user.id};
        if(ctx.esperando==='nequi') updates.nequi=lower.replace(/\s+/g,'');
        if(ctx.esperando==='bancol') updates.bancolombia=lower.replace(/\s+/g,'');
        if(ctx.esperando==='daviplata') updates.daviplata=lower.replace(/\s+/g,'');
        await supabase.from('user_configs').upsert(updates,{onConflict:'user_id'});
        const nombre={'nequi':'Nequi','bancol':'Bancolombia','daviplata':'Daviplata'}[ctx.esperando];
        await setCtxByPhone(phone,{step:'sub_pagos'});
        await sendWhatsApp(phone,`✅ *${nombre}* guardado!\n\n*1* Ver datos | *0* Menu`);
      } else { await mostrarSubmenu(phone,'pagos',user); }
      break;
    }
    case 'mercado': {
      if(lower==='1'){
        const {data:items}=await supabase.from('mercado').select('*').eq('user_id',user.id).eq('done',false).order('categoria');
        if(!items||!items.length){await sendWhatsApp(phone,`Lista vacia! 🎉\n\n*0* Menu`);return;}
        const porCat={};
        items.forEach(i=>{const c=i.categoria||'Otros';porCat[c]=(porCat[c]||[]).concat(i);});
        let msg=`🛒 *Lista completa (${items.length})*\n━━━━━━━━━━━━━━\n`;
        Object.keys(porCat).forEach(cat=>{msg+=`\n*${cat}:*\n`;porCat[cat].forEach(i=>{msg+=`  ☐ ${i.nombre}${i.cantidad?' ('+i.cantidad+')':''}\n`;});});
        await sendWhatsApp(phone,msg+`\n*0* Menu`);
      } else if(lower==='2'){
        await setCtxByPhone(phone,{step:'sub_mercado',esperando:'item_mercado'});
        await sendWhatsApp(phone,`Que producto necesitas?\n_"leche 2 litros"_\n\n*0* Cancelar`);
      } else if(ctx.esperando==='item_mercado'){
        await supabase.from('mercado').insert({user_id:user.id,nombre:lower.trim(),cantidad:null,categoria:'Otros',done:false});
        await setCtxByPhone(phone,{step:'sub_mercado'});
        await sendWhatsApp(phone,`✅ *${lower.trim()}* agregado!\n\n*1* Ver lista | *2* Agregar otro | *0* Menu`);
      } else { await mostrarSubmenu(phone,'mercado',user); }
      break;
    }
    case 'tareas': {
      if(lower==='1'){
        const {data:tareas}=await supabase.from('tasks').select('*').eq('user_id',user.id).eq('done',false).order('created_at',{ascending:false});
        if(!tareas||!tareas.length){await sendWhatsApp(phone,`Sin tareas pendientes! 🎉\n\n*0* Menu`);return;}
        const priIcon={alta:'🔴',media:'🟡',baja:'🔵'};
        await sendWhatsApp(phone,`✅ *Tareas (${tareas.length})*\n━━━━━━━━━━━━━━\n`+tareas.map(t=>`${priIcon[t.prioridad]||'⚪'} ${t.titulo}${t.fecha?' ('+t.fecha+')':''}`).join('\n')+`\n\n*0* Menu`);
      } else if(lower==='2'){
        await setCtxByPhone(phone,{step:'sub_tareas',esperando:'nueva_tarea'});
        await sendWhatsApp(phone,`Escribe la tarea:\n_"llamar al banco"_\n\n*0* Cancelar`);
      } else if(ctx.esperando==='nueva_tarea'){
        await supabase.from('tasks').insert({user_id:user.id,titulo:lower.trim(),prioridad:'media',done:false});
        await setCtxByPhone(phone,{step:'sub_tareas'});
        await sendWhatsApp(phone,`✅ *${lower.trim()}* agregada!\n\n*1* Ver tareas | *2* Otra | *0* Menu`);
      } else { await mostrarSubmenu(phone,'tareas',user); }
      break;
    }
    case 'servicios': {
      if(lower==='1'){
        const {data:servs}=await supabase.from('servicios').select('*').eq('user_id',user.id).order('dia');
        if(!servs||!servs.length){await sendWhatsApp(phone,`Sin servicios configurados.\n\nmilkomercios.in/MiCaja/servicios.html\n\n*0* Menu`);return;}
        const diaHoy=new Date().getDate();
        await sendWhatsApp(phone,`🔔 *Todos los servicios:*\n━━━━━━━━━━━━━━\n`+servs.map(s=>{
          if(s.pagado_mes)return `✅ ${s.icono} ${s.nombre}`;
          const diff=s.dia-diaHoy;
          if(diff<0)return `⚠️ ${s.icono} ${s.nombre} (vencido ${Math.abs(diff)}d)`;
          if(diff===0)return `🔴 ${s.icono} ${s.nombre} (HOY)`;
          if(diff<=3)return `🟡 ${s.icono} ${s.nombre} (en ${diff}d)`;
          return `🟢 ${s.icono} ${s.nombre} (dia ${s.dia})`;
        }).join('\n')+`\n\n*0* Menu`);
      } else if(lower==='2'){
        const {data:servs}=await supabase.from('servicios').select('*').eq('user_id',user.id).eq('pagado_mes',false).order('dia');
        if(!servs||!servs.length){await sendWhatsApp(phone,`Todo pagado! ✅\n\n*0* Menu`);return;}
        await setCtxByPhone(phone,{step:'sub_servicios',esperando:'marcar_pagado',ids:JSON.stringify(servs.map(s=>s.id))});
        await sendWhatsApp(phone,`Cual marcas como pagado?\n\n`+servs.map((s,i)=>`*${i+1}* ${s.icono} ${s.nombre}`).join('\n')+`\n\n*0* Cancelar`);
      } else if(ctx.esperando==='marcar_pagado'){
        const ids=JSON.parse(ctx.ids||'[]');
        const idx=parseInt(lower)-1;
        if(idx>=0&&idx<ids.length){
          await supabase.from('servicios').update({pagado_mes:true}).eq('id',ids[idx]);
          await setCtxByPhone(phone,{step:'sub_servicios'});
          await sendWhatsApp(phone,`✅ Marcado como pagado!\n\n*1* Ver servicios | *0* Menu`);
        } else { await sendWhatsApp(phone,`Numero invalido. Intenta de nuevo.`); }
      } else { await mostrarSubmenu(phone,'servicios',user); }
      break;
    }
    case 'informes': {
      const modMap={'1':user.plan,'2':user.plan,'3':'personal','4':'comerciantes','5':'parejas'};
      const titulos={'1':'Mes actual','2':'Historico completo','3':'Finanzas Personales','4':'Mi Negocio','5':'Finanzas en Pareja'};
      if(modMap[lower]){
        try{
          const mod=modMap[lower];
          let query=supabase.from('movements').select('*').eq('user_id',user.id).eq('module',mod).order('date',{ascending:false});
          if(lower==='1'){const a=new Date();const d=`${a.getFullYear()}-${String(a.getMonth()+1).padStart(2,'0')}-01`;query=query.gte('date',d);}
          const {data:movs}=await query;
          const fecha=new Date().toLocaleDateString('es-CO',{day:'2-digit',month:'long',year:'numeric'});
          const html=generarHTMLInforme(movs||[],titulos[lower],fecha,user.name);
          const token=crypto.randomBytes(16).toString('hex');
          await supabase.from('temp_files').insert({token,content:html,filename:`informe.html`,expires_at:new Date(Date.now()+24*60*60*1000).toISOString()});
          const inc=(movs||[]).filter(m=>m.type==='income').reduce((s,m)=>s+Number(m.amount),0);
          const exp=(movs||[]).filter(m=>m.type==='expense').reduce((s,m)=>s+Number(m.amount),0);
          await sendWhatsApp(phone,`📄 *${titulos[lower]}*\n💵 $${inc.toLocaleString()} | 💸 $${exp.toLocaleString()}\n${(inc-exp)>=0?'✅':'⚠️'} $${(inc-exp).toLocaleString()}\n\n📥 https://micaja-backend-production.up.railway.app/api/download/${token}\n_24 horas_\n\n*0* Menu`);
        }catch(e){await sendWhatsApp(phone,`Error. Intenta de nuevo.\n\n*0* Menu`);}
      } else { await mostrarSubmenu(phone,'informes',user); }
      break;
    }
    case 'modulo': {
      const opMap={'1':'personal','2':'comerciantes','3':'parejas','4':'viajes'};
      const plan=opMap[lower];
      if(plan){
        await supabase.from('users').update({plan}).eq('id',user.id);
        await setCtxByPhone(phone,{});
        await sendWhatsApp(phone,`✅ Modulo: *${planNames[plan]}* 💪\n\nEscribe *menu* para continuar`);
      } else { await mostrarSubmenu(phone,'modulo',user); }
      break;
    }
    default:
      await setCtxByPhone(phone,{});
      await sendWhatsApp(phone,`Escribe *menu* 😊`);
  }
}

// ══════ GENERADOR DE INFORME HTML UNIFICADO ══════
function generarHTMLInforme(movs, titulo, periodo, userName) {
  const COLORS_EXP = ['#EF4444','#DC2626','#F87171','#FCA5A5','#B91C1C','#991B1B'];
  const COLORS_INC = ['#25D366','#059669','#34D399','#3B82F6','#8B5CF6','#F59E0B'];
  const inc = movs.filter(m=>m.type==='income').reduce((s,m)=>s+Number(m.amount),0);
  const exp = movs.filter(m=>m.type==='expense').reduce((s,m)=>s+Number(m.amount),0);
  const util = inc - exp;
  const byCatExp = {}, byCatInc = {};
  movs.forEach(m=>{const c=m.category||'Otros';if(m.type==='expense')byCatExp[c]=(byCatExp[c]||0)+Number(m.amount);else byCatInc[c]=(byCatInc[c]||0)+Number(m.amount);});
  const totalExp = Object.values(byCatExp).reduce((s,v)=>s+v,0)||1;
  const totalInc = Object.values(byCatInc).reduce((s,v)=>s+v,0)||1;

  const bars = (byCat, total, colors) => Object.keys(byCat).sort((a,b)=>byCat[b]-byCat[a]).map((k,i)=>{
    const pct = Math.round((byCat[k]/total)*100);
    return `<div style="margin-bottom:7px"><div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:3px"><span><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${colors[i%colors.length]};margin-right:5px;vertical-align:middle"></span>${k}</span><span>$${byCat[k].toLocaleString()} - ${pct}%</span></div><div style="background:#F1F5F9;border-radius:4px;height:8px"><div style="width:${pct}%;height:8px;background:${colors[i%colors.length]};border-radius:4px"></div></div></div>`;
  }).join('');

  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>${titulo}</title>
<style>
body{font-family:Segoe UI,sans-serif;padding:28px;color:#0F172A}
h1{font-size:20px;font-weight:800;margin-bottom:3px}
.sub{color:#64748B;font-size:12px;margin-bottom:18px}
.cards{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:18px}
.card{border-radius:10px;padding:14px;text-align:center}
.val{font-size:18px;font-weight:800;margin:4px 0}
.lbl{font-size:11px;color:#64748B}
.charts{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:18px}
.chart-sec{border:1px solid #E2E8F0;border-radius:8px;padding:14px}
.chart-sec h3{font-size:12px;font-weight:700;margin-bottom:10px}
.movs h3{font-size:13px;font-weight:700;margin-bottom:8px;border-bottom:2px solid #E2E8F0;padding-bottom:6px}
.mov-row{display:flex;gap:8px;padding:4px 0;border-bottom:1px solid #F8FAFC;font-size:11px}
.footer{margin-top:20px;font-size:10px;color:#94A3B8;text-align:center;border-top:1px solid #E2E8F0;padding-top:10px}
</style></head><body>
<h1>${titulo}</h1>
<div class="sub">Informe - ${periodo} - ${new Date().toLocaleDateString('es-CO',{day:'2-digit',month:'long',year:'numeric'})}</div>
<div class="cards">
  <div class="card" style="background:#ECFDF5;border:1px solid #6EE7B7"><div class="val" style="color:#059669">$${inc.toLocaleString()}</div><div class="lbl">Ingresos</div></div>
  <div class="card" style="background:#FEF2F2;border:1px solid #FCA5A5"><div class="val" style="color:#EF4444">$${exp.toLocaleString()}</div><div class="lbl">Gastos</div></div>
  <div class="card" style="background:${util>=0?'#EFF6FF':'#FEF2F2'};border:1px solid ${util>=0?'#93C5FD':'#FCA5A5'}"><div class="val" style="color:${util>=0?'#2563EB':'#EF4444'}">${util>=0?'+':''}$${util.toLocaleString()}</div><div class="lbl">${titulo.includes('Negocio')?'Utilidad':'Balance'}</div></div>
</div>
<div class="charts">
  <div class="chart-sec"><h3>Gastos por categoria</h3>${Object.keys(byCatExp).length?bars(byCatExp,totalExp,COLORS_EXP):'<p style="color:#94A3B8;font-size:11px">Sin gastos</p>'}</div>
  <div class="chart-sec"><h3>Ingresos por categoria</h3>${Object.keys(byCatInc).length?bars(byCatInc,totalInc,COLORS_INC):'<p style="color:#94A3B8;font-size:11px">Sin ingresos</p>'}</div>
</div>
<div class="movs"><h3>Movimientos (${movs.length})</h3>
${movs.map(m=>`<div class="mov-row"><span style="width:8px;height:8px;border-radius:50%;background:${m.type==='income'?'#25D366':'#EF4444'};flex-shrink:0;margin-top:2px;display:inline-block"></span><span style="flex:1">${m.description}</span><span style="color:#94A3B8;min-width:80px">${m.category||''}</span><span style="color:#94A3B8;min-width:75px">${m.date}</span><span style="font-weight:700;color:${m.type==='income'?'#059669':'#EF4444'}">${m.type==='income'?'+':'-'}$${Number(m.amount).toLocaleString()}</span></div>`).join('')}
</div>
<div class="footer">MiCaja - milkomercios.in/MiCaja${userName?' - '+userName:''}</div>
</body></html>`;
}

// ══════ ENVIAR WHATSAPP ══════
async function sendWhatsApp(to, message) {
  if (!WA_TOKEN || !WA_PHONE_ID) { console.log(`[WA SIM] → ${to}: ${message.substring(0,50)}...`); return; }
  try {
    const phone = to.replace(/[+\s-]/g, '');
    await axios.post(`https://graph.facebook.com/v18.0/${WA_PHONE_ID}/messages`, { messaging_product: 'whatsapp', to: phone, type: 'text', text: { body: message } }, { headers: { 'Authorization': `Bearer ${WA_TOKEN}`, 'Content-Type': 'application/json' } });
    console.log(`✅ WA → ${phone}`);
  } catch (err) { console.error('WA Error:', err.response?.data || err.message); }
}

async function sendWhatsAppTemplate(to, templateName, params) {
  if (!WA_TOKEN || !WA_PHONE_ID) { console.log(`[WA TEMPLATE SIM] → ${to}: ${templateName}`); return; }
  try {
    const phone = to.replace(/[+\s-]/g, '');
    const components = params && params.length ? [{ type: 'body', parameters: params.map(p => ({ type: 'text', text: String(p) })) }] : [];
    await axios.post(`https://graph.facebook.com/v18.0/${WA_PHONE_ID}/messages`, { messaging_product: 'whatsapp', to: phone, type: 'template', template: { name: templateName, language: { code: 'es' }, components } }, { headers: { 'Authorization': `Bearer ${WA_TOKEN}`, 'Content-Type': 'application/json' } });
    console.log(`✅ WA Template "${templateName}" → ${phone}`);
  } catch (err) { console.error('WA Template Error:', err.response?.data || err.message); }
}

// ══════ ADMIN ══════
async function verifyAdmin(req, res, next) {
  const phone = req.headers['x-admin-phone'];
  if (!phone) return res.status(401).json({ error: 'No autorizado' });
  const { data: user } = await supabase.from('users').select('role').eq('phone', phone).single();
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'Solo administradores' });
  next();
}

app.get('/api/admin/users', verifyAdmin, async (req, res) => {
  try {
    const { data: users } = await supabase.from('users').select('*').order('created_at', { ascending: false });
    if (!users) return res.json({ ok: true, users: [] });
    const enriched = await Promise.all(users.map(async u => {
      const { data: movs } = await supabase.from('movements').select('type, amount').eq('user_id', u.id);
      const count = (movs||[]).length;
      const income = (movs||[]).filter(m => m.type==='income').reduce((s,m) => s+Number(m.amount), 0);
      const { pin: _, verify_code: __, ...safeUser } = u;
      return { ...safeUser, movement_count: count, income_total: income };
    }));
    res.json({ ok: true, users: enriched });
  } catch (err) { res.status(500).json({ error: 'Error al obtener usuarios' }); }
});

app.get('/api/admin/payments', verifyAdmin, async (req, res) => {
  try {
    const { data: payments } = await supabase.from('payments').select('*, users(name, phone)').order('created_at', { ascending: false }).limit(100);
    res.json({ ok: true, payments: payments || [] });
  } catch (err) { res.status(500).json({ error: 'Error al obtener pagos' }); }
});

app.put('/api/admin/users/:id', verifyAdmin, async (req, res) => {
  try {
    const { name, pin, plan, role, status } = req.body;
    const updates = {};
    if (name !== undefined) updates.name = name;
    if (pin && pin.length === 4 && /^\d{4}$/.test(pin)) updates.pin = pin;
    if (plan) updates.plan = plan;
    if (role) updates.role = role;
    if (status) updates.status = status;
    const { data, error } = await supabase.from('users').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;
    const { pin: _, ...safeUser } = data;
    res.json({ ok: true, user: safeUser });
  } catch (err) { res.status(500).json({ error: 'Error al actualizar usuario' }); }
});

app.get('/api/admin/users/:id/data', verifyAdmin, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('*').eq('id', req.params.id).single();
    if (!user) return res.status(404).json({ error: 'No encontrado' });
    const { data: movs } = await supabase.from('movements').select('*').eq('user_id', req.params.id).order('created_at', { ascending: false });
    const { data: trips } = await supabase.from('trips').select('*, trip_expenses(*)').eq('user_id', req.params.id);
    const income = (movs||[]).filter(m => m.type==='income').reduce((s,m) => s+Number(m.amount), 0);
    const expense = (movs||[]).filter(m => m.type==='expense').reduce((s,m) => s+Number(m.amount), 0);
    const { pin: _, ...safeUser } = user;
    res.json({ ok: true, user: safeUser, summary: { income, expense, balance: income-expense, count: (movs||[]).length }, movements: movs||[], trips: trips||[] });
  } catch (err) { res.status(500).json({ error: 'Error al obtener datos' }); }
});

// ══════ USUARIOS ══════
app.get('/api/users/:id/config', async (req, res) => {
  try {
    const { data } = await supabase.from('user_config').select('*').eq('user_id', req.params.id).single();
    res.json({ ok: true, config: data || null });
  } catch (err) { res.json({ ok: true, config: null }); }
});

app.post('/api/users/:id/config', async (req, res) => {
  try {
    const { partner_name, partner_income_a, partner_income_b } = req.body;
    const { data, error } = await supabase.from('user_config').upsert({ user_id: req.params.id, partner_name, partner_income_a, partner_income_b, updated_at: new Date() }, { onConflict: 'user_id' }).select().single();
    if (error) throw error;
    res.json({ ok: true, config: data });
  } catch (err) { res.status(500).json({ error: 'Error al guardar configuración' }); }
});

app.put('/api/users/:id', async (req, res) => {
  try {
    const allowed = ['name', 'business_name', 'partner_name', 'plan'];
    const updates = {};
    allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });
    if (!Object.keys(updates).length) return res.status(400).json({ error: 'Sin campos para actualizar' });
    const { data, error } = await supabase.from('users').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;
    const { pin: _, verify_code: __, ...safeUser } = data;
    res.json({ ok: true, user: safeUser });
  } catch (err) { res.status(500).json({ error: 'Error al actualizar' }); }
});

// ══════ DEUDAS ══════
app.get('/api/debts/:userId', async (req, res) => {
  try {
    const { data, error } = await supabase.from('debts').select('*').eq('user_id', req.params.userId).order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ ok: true, debts: data || [] });
  } catch (err) { res.status(500).json({ error: 'Error al obtener deudas' }); }
});

app.post('/api/debts', async (req, res) => {
  try {
    const { user_id, type, person_name, amount, description, due_date, note, loan_date } = req.body;
    if (!user_id || !type || !person_name || !amount) return res.status(400).json({ error: 'Campos requeridos' });
    const { data, error } = await supabase.from('debts').insert({ user_id, type, person_name, amount, description, due_date: due_date||null, note, loan_date: loan_date||null, status: 'pending', paid: 0 }).select().single();
    if (error) throw error;
    res.json({ ok: true, debt: data });
  } catch (err) { res.status(500).json({ error: 'Error al crear deuda' }); }
});

app.post('/api/debts/:id/abono', async (req, res) => {
  try {
    const { amount } = req.body;
    const { data: debt } = await supabase.from('debts').select('amount, paid').eq('id', req.params.id).single();
    if (!debt) return res.status(404).json({ error: 'No encontrada' });
    const newPaid = Number(debt.paid||0) + Number(amount);
    const newStatus = newPaid >= Number(debt.amount) ? 'paid' : 'partial';
    const { data, error } = await supabase.from('debts').update({ paid: newPaid, status: newStatus }).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json({ ok: true, debt: data });
  } catch (err) { res.status(500).json({ error: 'Error al registrar abono' }); }
});

app.put('/api/debts/:id', async (req, res) => {
  try {
    const { person_name, amount, description, due_date, note, loan_date } = req.body;
    const updates = {};
    if (person_name !== undefined) updates.person_name = person_name;
    if (amount !== undefined) updates.amount = amount;
    if (description !== undefined) updates.description = description;
    if (due_date !== undefined) updates.due_date = due_date || null;
    if (note !== undefined) updates.note = note;
    if (loan_date !== undefined) updates.loan_date = loan_date || null;
    const { data, error } = await supabase.from('debts').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json({ ok: true, debt: data });
  } catch (err) { res.status(500).json({ error: 'Error al actualizar deuda' }); }
});

app.put('/api/debts/:id/paid', async (req, res) => {
  try {
    const { data: debt } = await supabase.from('debts').select('amount').eq('id', req.params.id).single();
    await supabase.from('debts').update({ status: 'paid', paid: debt.amount }).eq('id', req.params.id);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.delete('/api/debts/:id', async (req, res) => {
  try {
    await supabase.from('debts').delete().eq('id', req.params.id);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Error' }); }
});

// ══════ PAGOS BOLD ══════
app.get('/api/payments/link/:phone', async (req, res) => {
  try {
    const phone = req.params.phone;
    const { data: user } = await supabase.from('users').select('*').eq('phone', phone).single();
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    const orderId = `MICAJA-${user.id.slice(0,8)}-${Date.now()}`;
    const integString = `${orderId}20000COP${BOLD_SECRET_KEY}`;
    const integritySignature = crypto.createHash('sha256').update(integString).digest('hex');
    const token = crypto.createHash('sha256').update(`${phone}-${Date.now()}-${BOLD_SECRET_KEY}`).digest('hex').slice(0, 16);
    const tokenExpiry = Date.now() + 30*60*1000;
    await supabase.from('payments').insert({ user_id: user.id, amount: 20000, method: 'bold', reference: orderId, status: 'pending', pay_token: token, token_expiry: tokenExpiry, period_start: new Date().toISOString().split('T')[0], period_end: new Date(Date.now() + 30*24*60*60*1000).toISOString().split('T')[0] });
    res.json({ ok: true, url: `https://milkomercios.in/MiCaja/pagar.html?tel=${phone}&token=${token}` });
  } catch (err) { res.status(500).json({ error: 'Error generando link' }); }
});

app.get('/api/payments/token/:phone/:token', async (req, res) => {
  try {
    const { phone, token } = req.params;
    const { data: user } = await supabase.from('users').select('id').eq('phone', phone).single();
    if (!user) return res.status(404).json({ error: 'Token no encontrado' });
    const { data: payment } = await supabase.from('payments').select('*').eq('user_id', user.id).eq('pay_token', token).eq('status', 'pending').order('created_at', { ascending: false }).limit(1).single();
    if (!payment) return res.status(404).json({ error: 'Token no encontrado' });
    if (payment.token_expiry < Date.now()) return res.status(401).json({ error: 'Token expirado' });
    const integString = `${payment.reference}20000COP${BOLD_SECRET_KEY}`;
    const integritySignature = crypto.createHash('sha256').update(integString).digest('hex');
    res.json({ ok: true, orderId: payment.reference, amount: '20000', currency: 'COP', integritySignature, apiKey: BOLD_API_KEY, redirectionUrl: 'https://milkomercios.in/MiCaja/pagar.html', description: 'MiCaja - Suscripción mensual $20.000' });
  } catch (err) { res.status(500).json({ error: 'Error verificando token' }); }
});

app.post('/api/payments/create', async (req, res) => {
  try {
    const { user_id, plan_type = 'mensual' } = req.body;
    if (!user_id) return res.status(400).json({ error: 'user_id requerido' });
    const { data: user } = await supabase.from('users').select('name, phone').eq('id', user_id).single();
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    const plans = { mensual: { amount: '20000', label: 'Suscripción mensual $20.000', days: 30 }, anual: { amount: '200000', label: 'Suscripción anual $200.000', days: 365 }, lifetime: { amount: '320000', label: 'Acceso de por vida $320.000', days: 36500 } };
    const plan = plans[plan_type] || plans.mensual;
    const orderId = `MICAJA-${user_id.slice(0,8)}-${Date.now()}`;
    const integString = `${orderId}${plan.amount}COP${BOLD_SECRET_KEY}`;
    const integritySignature = crypto.createHash('sha256').update(integString).digest('hex');
    await supabase.from('payments').insert({ user_id, amount: parseInt(plan.amount), method: 'bold', reference: orderId, status: 'pending', plan_type, period_start: new Date().toISOString().split('T')[0], period_end: new Date(Date.now() + plan.days*24*60*60*1000).toISOString().split('T')[0] });
    res.json({ ok: true, orderId, amount: plan.amount, currency: 'COP', integritySignature, apiKey: BOLD_API_KEY, redirectionUrl: 'https://milkomercios.in/MiCaja/dashboard.html', description: plan.label });
  } catch (err) { res.status(500).json({ error: 'Error al crear pago' }); }
});

app.post('/api/payments/bold-webhook', async (req, res) => {
  try {
    const event = req.body;
    if (event.type !== 'TRANSACTION' || event.data?.transaction?.status !== 'APPROVED') return res.sendStatus(200);
    const orderId = event.data?.transaction?.order_id || event.data?.transaction?.orderId;
    if (!orderId) return res.sendStatus(200);
    const parts = orderId.split('-');
    if (parts.length < 2) return res.sendStatus(200);
    const userIdPrefix = parts[1];
    const { data: payment } = await supabase.from('payments').select('*, users(*)').ilike('reference', `MICAJA-${userIdPrefix}%`).eq('status', 'pending').order('created_at', { ascending: false }).limit(1).single();
    if (!payment) return res.sendStatus(200);
    await supabase.from('payments').update({ status: 'paid' }).eq('id', payment.id);
    await supabase.from('users').update({ status: 'active' }).eq('id', payment.user_id);
    const userPhone = payment.users?.phone;
    if (userPhone && WA_TOKEN) await sendWhatsApp(userPhone, `✅ *¡Pago recibido!*\n\n💰 $20.000 COP — MiCaja mensual\n📅 Válido hasta: ${payment.period_end}\n🔢 Ref: ${orderId}\n\n¡Gracias! Tu acceso está activo 🚀\n🌐 milkomercios.in/MiCaja/dashboard.html`);
    res.sendStatus(200);
  } catch (err) { console.error('Bold webhook error:', err); res.sendStatus(200); }
});

app.get('/api/payments/status/:userId', async (req, res) => {
  try {
    const { data: payment } = await supabase.from('payments').select('*').eq('user_id', req.params.userId).eq('status', 'paid').order('created_at', { ascending: false }).limit(1).single();
    if (!payment) return res.json({ ok: true, active: false });
    const expired = payment.period_end < new Date().toISOString().split('T')[0];
    res.json({ ok: true, active: !expired, payment });
  } catch (err) { res.json({ ok: true, active: false }); }
});

// ══════ INICIAR ══════
app.listen(PORT, () => {
  console.log(`⚡ MiCaja Backend v2.2 en puerto ${PORT}`);
  console.log(`📊 Supabase: ${SUPABASE_URL ? '✅' : '⚠️'}`);
  console.log(`📱 WhatsApp: ${WA_TOKEN ? '✅' : '⚠️ simulado'}`);
  console.log(`💳 Bold: ${BOLD_API_KEY ? '✅' : '⚠️ sin configurar'}`);
  console.log(`🛡️ Rate limiting: ✅ activo`);
  console.log(`🔧 Fix sesiones v2.2: ✅ activo`);
});
