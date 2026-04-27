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
    if (!user.magic_token_expiry || Number(user.magic_token_expiry) < Date.now()) {
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
// SESIONES — cache en memoria + Supabase backup
// El Map local resuelve race condition de latencia de DB
// ══════════════════════════════════════
const sessionCache = new Map();

async function setCtxByPhone(phone, newCtx) {
  sessionCache.set(phone, { ctx: newCtx, ts: Date.now() });
  supabase.from('wa_sessions').upsert(
    { phone, context: JSON.stringify(newCtx), updated_at: new Date().toISOString() },
    { onConflict: 'phone' }
  ).then(() => {}).catch(() => {});
}

async function getCtxByPhone(phone) {
  const cached = sessionCache.get(phone);
  if (cached) {
    const age = Date.now() - cached.ts;
    const step = cached.ctx && cached.ctx.step;
    const limit = step === 'menu_principal' ? 2*60*60*1000 :
                  step === 'confirm_cat' ? 30*60*1000 :
                  step && step.startsWith('sub_') ? 60*60*1000 : 30*60*1000;
    if (age < limit) return cached.ctx || {};
    sessionCache.delete(phone);
  }
  try {
    const { data: session } = await supabase.from('wa_sessions')
      .select('context, updated_at').eq('phone', phone).single();
    if (!session || !session.context) return {};
    const ctx = JSON.parse(session.context);
    if (ctx.step && session.updated_at) {
      const age = Date.now() - new Date(session.updated_at).getTime();
      const limit = ctx.step === 'menu_principal' ? 2*60*60*1000 :
                    ctx.step === 'confirm_cat' ? 30*60*1000 :
                    ctx.step.startsWith('sub_') ? 60*60*1000 : 30*60*1000;
      if (age > limit) return {};
    }
    sessionCache.set(phone, { ctx, ts: Date.now() });
    return ctx;
  } catch { return {}; }
}

// ══════════════════════════════════════
// PROCESAR MENSAJES DE WHATSAPP
// ══════════════════════════════════════

// ══════════════════════════════════════
// PROCESAR MENSAJES DE WHATSAPP v2.3
// Menú navegable con módulos reales
// ══════════════════════════════════════
async function processWhatsAppMessage(phone, text) {
  let { data: user } = await supabase.from('users').select('*').eq('phone', phone).single();

  const lower = text.toLowerCase().trim()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[¿¡]/g, '');

  const ctx = await getCtxByPhone(phone);
  const setCtx  = (newCtx) => setCtxByPhone(phone, newCtx);
  const clearCtx = ()      => setCtxByPhone(phone, {});

  // ══════ SIN CUENTA ══════
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

  // ══════ COMANDOS GLOBALES — siempre funcionan ══════
  if (['cancelar','cancel','reset','reiniciar','limpiar','salir','exit'].includes(lower)) {
    await clearCtx();
    await sendWhatsApp(phone, `✅ Listo.\n\nEscribe *hola* o *menu* para empezar 😊`);
    return;
  }

  // ══════ LINK WEB — siempre disponible sin importar el ctx ══════
  if (/^(web|link|portal|app|aplicacion|aplicación|dashboard|login|acceso|acceso web|ir a la web|abrir app|micaja web)$/.test(lower)) {
    try {
      const magicToken = crypto.randomBytes(20).toString('hex');
      await supabase.from('users').update({ magic_token: magicToken, magic_token_expiry: Date.now() + 10*60*1000 }).eq('id', user.id);
      await sendWhatsApp(phone,
        `🔐 *Tu acceso directo a MiCaja:*

` +
        `👉 https://milkomercios.in/MiCaja/login.html?magic=${magicToken}

` +
        `⏱ _Expira en 10 minutos, un solo uso._
` +
        `_Nadie más puede usarlo — es solo tuyo._`
      );
    } catch(e) {
      await sendWhatsApp(phone, `🌐 milkomercios.in/MiCaja/login.html

📱 ${phone}
🔐 PIN: ${user.pin}`);
    }
    return;
  }

  // ══════ SALUDO ══════
  if (['hola','hi','hey','buenas','buenos dias','buenas tardes','buenas noches','que mas','inicio','start'].includes(lower)) {
    await clearCtx();
    const hour = new Date(new Date().toLocaleString('en-US',{timeZone:'America/Bogota'})).getHours();
    const saludo = hour < 12 ? 'Buenos días' : hour < 18 ? 'Buenas tardes' : 'Buenas noches';
    const planNames = {personal:'👤 Personal',parejas:'💑 Pareja',viajes:'✈️ Viajes',comerciantes:'🏪 Negocio'};
    const { data: movs } = await supabase.from('movements').select('type, amount').eq('user_id', user.id).eq('module', user.plan);
    const bal = (movs||[]).reduce((s,m) => s + (m.type==='income' ? Number(m.amount) : -Number(m.amount)), 0);
    await sendWhatsApp(phone,
      `${saludo} *${user.name||''}* 👋\n\n` +
      `Módulo activo: *${planNames[user.plan]}*\n` +
      `${movs&&movs.length ? `Balance: *$${bal.toLocaleString()}* COP\n` : ''}\n` +
      `Escribe *menu* para ver todas las opciones\n` +
      `O registra directamente:\n` +
      `💸 _"pagué luz 80mil"_\n` +
      `💵 _"me ingresaron 2 millones"_`
    );
    return;
  }

  // ══════ PIN ══════
  const pinConsulta = /^(mi\s+)?pin$|^(cual)\s+es\s+mi\s+pin|^(olvide|recuperar|recordar|ver)\s+(mi\s+)?pin|^pin\?$/i;
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

  // ══════ MÓDULO — cambio directo ══════
  const moduloMatch = lower.match(/^(?:modulo|cambiar\s+modulo|cambiar\s+a|quiero\s+el\s+modulo|quiero\s+modulo|usar\s+modulo)\s+(.+)/i);
  if (moduloMatch) {
    const planMap = {personal:'personal',finanzas:'personal',pareja:'parejas',parejas:'parejas',viaje:'viajes',viajes:'viajes',negocio:'comerciantes',comercio:'comerciantes',comerciante:'comerciantes'};
    const plan = planMap[moduloMatch[1].trim().toLowerCase()];
    if (plan) {
      await supabase.from('users').update({plan}).eq('id', user.id);
      const planNames = {personal:'👤 Personal',parejas:'💑 Pareja',viajes:'✈️ Viajes',comerciantes:'🏪 Negocio'};
      await sendWhatsApp(phone, `✅ Módulo cambiado a *${planNames[plan]}* 💪\n\nEscribe *menu* para continuar`);
    } else {
      await sendWhatsApp(phone, `Módulos disponibles:\n*personal* · *pareja* · *viajes* · *negocio*\n\nEjemplo: _"modulo negocio"_`);
    }
    return;
  }

  // ══════ ATAJOS DIRECTOS — palabras clave sin menú ══════
  // Mercado
  if (/^(mi\s+)?(lista\s+(de\s+)?)?mercado$|^mis?\s+compras?$|^lista\s+compras?$/.test(lower)) {
    await mostrarSubmenu(phone, 'mercado', user); return;
  }
  // Tareas
  if (/^(mis?\s+)?tareas?$|^pendientes?$|^(mis?\s+)?pendientes?$|^lista\s+tareas?$|^que\s+tengo\s+pendiente$/.test(lower)) {
    await mostrarSubmenu(phone, 'tareas', user); return;
  }
  // Servicios
  if (/^(mis?\s+)?servicios?(\s+publicos?)?$|^vencimientos?$|^pagos?\s+mes$|^servicios?\s+y\s+pagos?$/.test(lower)) {
    await mostrarSubmenu(phone, 'servicios', user); return;
  }
  // Deudas
  if (/^(mis?\s+)?deudas?$|^ver\s+deudas?$|^estado\s+deudas?$/.test(lower)) {
    await mostrarSubmenu(phone, 'deudas', user); return;
  }
  // Módulos / cambiar módulo
  if (/^modulos?$|^mi\s+modulo$|^modulo\s+actual$|^en\s+que\s+modulo(\s+estoy)?$|^que\s+modulo(\s+tengo)?$|^cambiar\s+modulo$/.test(lower)) {
    await mostrarSubmenu(phone, 'modulo', user); return;
  }
  // Informes
  if (/^informes?$|^reportes?$|^ver\s+informe$|^mis?\s+informes?$/.test(lower)) {
    await mostrarSubmenu(phone, 'informes', user); return;
  }
  // Negocio directo
  if (/^(mi\s+)?negocio$|^comerciantes?$/.test(lower)) {
    await mostrarSubmenu(phone, 'negocio', user); return;
  }
  // Pareja directo
  if (/^pareja$|^finanzas\s+pareja$|^gastos\s+pareja$/.test(lower)) {
    await mostrarSubmenu(phone, 'pareja', user); return;
  }
  // Viajes directo
  if (/^viajes?$|^mis?\s+viajes?$/.test(lower)) {
    await mostrarSubmenu(phone, 'viajes', user); return;
  }
  // Métodos de pago directo
  if (/^(mis?\s+)?(metodos?\s+(de\s+)?pago|llaves?|datos?\s+(de\s+)?pago|nequi|bancol|daviplata)$/.test(lower)) {
    await mostrarSubmenu(phone, 'pagos', user); return;
  }

  // ══════ MENÚ PRINCIPAL ══════
  const esMenu = ['menu','menues','modulo','modulos','mi modulo','opciones','que puedes hacer','comandos','ayuda','help','inicio menu','volver al menu'].includes(lower);
  if (esMenu) {
    await setCtxByPhone(phone, { step: 'menu_principal' });
    await enviarMenuPrincipal(phone, user);
    return;
  }

  // ══════ NAVEGACIÓN DESDE MENÚ PRINCIPAL ══════
  if (ctx.step === 'menu_principal') {
    const menuMap = {
      '1':'negocio',   'negocio':'negocio',    'mi negocio':'negocio',
      '2':'pareja',    'pareja':'pareja',       'parejas':'pareja',        'finanzas pareja':'pareja',
      '3':'viajes',    'viajes':'viajes',       'viaje':'viajes',
      '4':'personal',  'personal':'personal',   'finanzas':'personal',     'mis finanzas':'personal',
      '5':'deudas',    'deudas':'deudas',       'mis deudas':'deudas',
      '6':'pagos',     'metodos de pago':'pagos','mis pagos':'pagos',      'nequi':'pagos',
      '7':'mercado',   'mercado':'mercado',     'lista mercado':'mercado', 'mi mercado':'mercado',
      '8':'tareas',    'tareas':'tareas',       'mis tareas':'tareas',
      '9':'informes',  'informes':'informes',   'informe':'informes',      'reportes':'informes',
    };
    const dest = menuMap[lower];
    if (dest) {
      await mostrarSubmenu(phone, dest, user);
    } else {
      await sendWhatsApp(phone, `Elige una opción del *1* al *9*\n\nEscribe *menu* para ver las opciones`);
    }
    return;
  }

  // ══════ NAVEGACIÓN DENTRO DE SUBMENÚ ══════
  if (ctx.step && ctx.step.startsWith('sub_')) {
    const submenuActual = ctx.step.replace('sub_','');
    if (['0','volver','atras','menu','salir','back','inicio'].includes(lower)) {
      await setCtxByPhone(phone, { step: 'menu_principal' });
      await enviarMenuPrincipal(phone, user);
      return;
    }

    // Módulos financieros: texto libre → parser directo sin salir del módulo
    if (['negocio','pareja','personal'].includes(submenuActual) && !ctx.esperando && !ctx.step2) {
      if (!/^[1-6]$/.test(lower) && !['resumen','pdf','informe','ultimos','cancelar','como voy','saldo'].includes(lower)) {
        const parsed = await parseWithAI(lower, user.name, user.plan);
        if (parsed) {
          const planNames = {personal:'👤 Personal',parejas:'💑 Pareja',viajes:'✈️ Viajes',comerciantes:'🏪 Negocio'};
          await setCtxByPhone(phone, { step: 'confirm_cat', type: parsed.type, amount: parsed.amount, description: parsed.description, category: parsed.category, returnTo: ctx.step });
          await sendWhatsApp(phone,
            `${parsed.type==='income'?'💵':'💸'} *¿Confirmas este ${parsed.type==='income'?'ingreso':'gasto'}?*\n\n` +
            `📝 *${parsed.description}*\n` +
            `💰 ${parsed.type==='income'?'+':'-'}$${Number(parsed.amount).toLocaleString()} COP\n` +
            `📂 Categoría: *${parsed.category}*\n` +
            `📋 Módulo: *${planNames[user.plan]}*\n\n` +
            `✅ *sí* — guardar\n` +
            `🔢 *1-12* — cambiar categoría\n` +
            `❌ *no* — cancelar\n\n` +
            `_1.Alimentación 2.Arriendo 3.Servicios 4.Transporte 5.Salud 6.Entretenimiento 7.Educación 8.Nómina 9.Proveedores 10.Créditos 11.Ventas 12.Otros_`
          );
          return;
        }
        await mostrarSubmenu(phone, submenuActual, user);
        return;
      }
    }

    await manejarSubmenu(phone, submenuActual, lower, text, user, ctx);
    return;
  }

  // ══════ INFORME ══════
  if (['informe','pdf','reporte','informe del mes','mi informe','ver informe'].includes(lower) || /informe\s*(del\s*)?(mes|semana|año|ano|todo)/i.test(lower)) {
    await generarYEnviarPDF(phone, user, user.plan);
    return;
  }

  // ══════ RESUMEN / BALANCE ══════
  if (['resumen','balance','como voy','cuanto llevo','estado','saldo'].includes(lower)) {
    await enviarResumen(phone, user, user.plan);
    return;
  }

  // ══════ DEUDAS RÁPIDAS ══════
  const deboMatch = lower.match(/(?:le debo|debo)\s+(\d+[\d.,]*\s*(?:mil|k|m)?)\s+(?:a|le a)?\s*(.+)/i);
  const meDebenMatch = lower.match(/(.+)\s+me debe\s+(\d+[\d.,]*\s*(?:mil|k|m)?)/i);
  if (deboMatch) {
    const amount = parsearMonto(deboMatch[1]);
    const persona = deboMatch[2].trim();
    await supabase.from('debts').insert({ user_id: user.id, type: 'debo', person_name: persona, amount, status: 'pending', paid: 0 });
    await sendWhatsApp(phone, `💸 Le debes *$${amount.toLocaleString()}* a *${persona}*\n\nEscribe _"deudas"_ para ver el estado.`);
    return;
  }
  if (meDebenMatch) {
    const persona = meDebenMatch[1].trim();
    const amount = parsearMonto(meDebenMatch[2]);
    await supabase.from('debts').insert({ user_id: user.id, type: 'me_deben', person_name: persona, amount, status: 'pending', paid: 0 });
    await sendWhatsApp(phone, `💵 *${persona}* te debe *$${amount.toLocaleString()}*\n\nEscribe _"deudas"_ para ver el estado.`);
    return;
  }



  // ══════ BORRAR ÚLTIMO ══════
  if (['borrar ultimo','borrar último','borrar','deshacer'].includes(lower)) {
    const { data: last } = await supabase.from('movements').select('id,description,amount,type').eq('user_id', user.id).eq('module', user.plan).order('created_at',{ascending:false}).limit(1).single();
    if (last) {
      await supabase.from('movements').delete().eq('id', last.id);
      await sendWhatsApp(phone, `🗑 Borré: ${last.type==='income'?'💵':'💸'} *${last.description}* — $${Number(last.amount).toLocaleString()}`);
    } else { await sendWhatsApp(phone, `No tienes movimientos para borrar 📭`); }
    return;
  }

  // ══════ VER ÚLTIMOS ══════
  if (['ultimos','últimos','mis movimientos','ver movimientos'].includes(lower)) {
    const { data: movs } = await supabase.from('movements').select('*').eq('user_id', user.id).eq('module', user.plan).order('created_at',{ascending:false}).limit(5);
    if (!movs||!movs.length) { await sendWhatsApp(phone, `No tienes movimientos aún 📭`); return; }
    const lista = movs.map((m,i) => `${i+1}. ${m.type==='income'?'💵':'💸'} ${m.description} — $${Number(m.amount).toLocaleString()}\n   📂 ${m.category} · ${m.date}`).join('\n\n');
    await sendWhatsApp(phone, `🕐 *Últimos 5 movimientos:*\n\n${lista}`);
    return;
  }

  // ══════ CONFIRMACIÓN CATEGORÍA ══════
  if (ctx.step === 'confirm_cat') {
    const cats = {'1':'Alimentación','2':'Arriendo','3':'Servicios','4':'Transporte','5':'Salud','6':'Entretenimiento','7':'Educación','8':'Nómina','9':'Proveedores','10':'Créditos','11':'Ventas','12':'Otros'};
    if (['cancelar','no','cancel'].includes(lower)) {
      await clearCtx();
      await sendWhatsApp(phone, `❌ Cancelado.\n\nEscríbeme cuando quieras 😊`);
      return;
    }
    const useCat = cats[lower] || Object.values(cats).find(c => c.toLowerCase() === lower) ||
      (['si','sí','ok','listo','dale','correcto','exacto','eso','así','asi','guardalo','guardar'].includes(lower) ? ctx.category : null);
    if (useCat) {
      const { error } = await supabase.from('movements').insert({
        user_id: user.id, type: ctx.type, amount: ctx.amount,
        description: ctx.description, category: useCat,
        source: 'whatsapp', module: user.plan
      });
      await clearCtx();
      if (!error) {
        const { data: movs } = await supabase.from('movements').select('type, amount').eq('user_id', user.id).eq('module', user.plan);
        const bal = (movs||[]).reduce((s,m) => s + (m.type==='income' ? Number(m.amount) : -Number(m.amount)), 0);
        await sendWhatsApp(phone,
          `✅ *${ctx.type==='income'?'Ingreso':'Gasto'} guardado*\n\n` +
          `${ctx.type==='income'?'💵':'💸'} ${ctx.description}\n` +
          `💰 ${ctx.type==='income'?'+':'-'}$${Number(ctx.amount).toLocaleString()} COP\n` +
          `📂 ${useCat}\n\n` +
          `Balance: *${bal>=0?'+':''}$${bal.toLocaleString()}* ${bal<0?'⚠️':'👍'}\n\n` +
          `_Registra otro o escribe *menu*_`
        );
        if (ctx.returnTo) { await setCtxByPhone(phone, { step: ctx.returnTo }); }
        else { await setCtxByPhone(phone, {}); }
      } else { await sendWhatsApp(phone, `❌ Error al guardar. Intenta de nuevo.`); }
    } else {
      await sendWhatsApp(phone,
        `Responde con el número:\n\n` +
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

  // ══════ GUARDAR MÉTODOS DE PAGO RÁPIDO ══════
  const nequiMatch  = lower.match(/mi\s+nequi\s+(?:es\s+|:?\s*)([\d\s]+)/i);
  const bancolMatch = lower.match(/mi\s+bancol(?:ombia)?\s+(?:es\s+|:?\s*)([\d\s]+)/i);
  const daviMatch   = lower.match(/mi\s+daviplata\s+(?:es\s+|:?\s*)([\d\s]+)/i);
  if (nequiMatch||bancolMatch||daviMatch) {
    const updates = { user_id: user.id };
    if(nequiMatch)  updates.nequi       = nequiMatch[1].trim().replace(/\s+/g,'');
    if(bancolMatch) updates.bancolombia = bancolMatch[1].trim().replace(/\s+/g,'');
    if(daviMatch)   updates.daviplata   = daviMatch[1].trim().replace(/\s+/g,'');
    await supabase.from('user_configs').upsert(updates, {onConflict:'user_id'});
    const tipo  = nequiMatch?'Nequi':bancolMatch?'Bancolombia':'Daviplata';
    const valor = (nequiMatch||bancolMatch||daviMatch)[1].trim();
    await sendWhatsApp(phone, `✅ *${tipo}* guardado: ${valor}\n\nEscribe _"metodos de pago"_ para verlos`);
    return;
  }

  // ══════ PARSER IA — registrar movimiento ══════
  const parsed = await parseWithAI(lower, user.name, user.plan);
  if (parsed) {
    const planNames = {personal:'👤 Personal',parejas:'💑 Pareja',viajes:'✈️ Viajes',comerciantes:'🏪 Negocio'};
    await setCtx({step:'confirm_cat', type:parsed.type, amount:parsed.amount, description:parsed.description, category:parsed.category});
    await sendWhatsApp(phone,
      `${parsed.type==='income'?'💵':'💸'} *¿Confirmas este ${parsed.type==='income'?'ingreso':'gasto'}?*\n\n` +
      `📝 *${parsed.description}*\n` +
      `💰 ${parsed.type==='income'?'+':'-'}$${Number(parsed.amount).toLocaleString()} COP\n` +
      `📂 Categoría: *${parsed.category}*\n` +
      `📋 Módulo: *${planNames[user.plan]}*\n\n` +
      `✅ *sí* — guardar\n` +
      `🔢 *1-12* — cambiar categoría\n` +
      `❌ *no* — cancelar\n\n` +
      `_1.Alimentación 2.Arriendo 3.Servicios 4.Transporte 5.Salud 6.Entretenimiento 7.Educación 8.Nómina 9.Proveedores 10.Créditos 11.Ventas 12.Otros_`
    );
    return;
  }

  await sendWhatsApp(phone, `Mmm, no entendí bien 🤔\n\nPrueba así:\n💸 _"pagué arriendo 800mil"_\n💵 _"me cayó el sueldo 2 millones"_\n\nO escribe *menu* para ver todo 😊`);
}

// ══════════════════════════════════════
// MENÚ PRINCIPAL — helper reutilizable
// ══════════════════════════════════════
async function enviarMenuPrincipal(phone, user) {
  const planNames = {personal:'👤 Personal',parejas:'💑 Pareja',viajes:'✈️ Viajes',comerciantes:'🏪 Negocio'};
  await sendWhatsApp(phone,
    `🤖 *MiCaja — Menú principal*\n` +
    `Módulo activo: *${planNames[user.plan]}*\n\n` +
    `*1* 🏪 Mi negocio — ventas y gastos del negocio\n` +
    `*2* 💑 Pareja — gastos compartidos con tu pareja\n` +
    `*3* ✈️ Viajes — gastos de un viaje grupal\n` +
    `*4* 👤 Personal — finanzas personales del día a día\n` +
    `*5* 💸 Deudas — lo que debes y lo que te deben\n` +
    `*6* 💳 Métodos de pago — Nequi, Bancolombia, etc\n` +
    `*7* 🛒 Lista de mercado — productos por comprar\n` +
    `*8* ✅ Tareas — pendientes y recordatorios\n` +
    `*9* 📊 Informes — PDF descargable de tus finanzas\n\n` +
    `Escribe el número o el nombre del módulo`
  );
}

// ══════════════════════════════════════
// RESUMEN — helper reutilizable
// ══════════════════════════════════════
async function enviarResumen(phone, user, mod) {
  const planNames = {personal:'Finanzas Personales',parejas:'Finanzas en Pareja',viajes:'Viajes',comerciantes:'Mi Negocio'};
  const { data: movs } = await supabase.from('movements').select('*').eq('user_id', user.id).eq('module', mod);
  const inc = (movs||[]).filter(m=>m.type==='income').reduce((s,m)=>s+Number(m.amount),0);
  const exp = (movs||[]).filter(m=>m.type==='expense').reduce((s,m)=>s+Number(m.amount),0);
  const bal = inc - exp;
  if (!(movs||[]).length) { await sendWhatsApp(phone, `Aún no tienes movimientos en *${planNames[mod]}* 📭\n\nEscribe _"pagué luz 80mil"_ para empezar.`); return; }
  const byCat = {};
  (movs||[]).filter(m=>m.type==='expense').forEach(m=>{ byCat[m.category]=(byCat[m.category]||0)+Number(m.amount); });
  const topCats = Object.entries(byCat).sort((a,b)=>b[1]-a[1]).slice(0,4).map(([c,v])=>`  • ${c}: $${v.toLocaleString()}`).join('\n');
  const last3 = (movs||[]).sort((a,b)=>new Date(b.created_at)-new Date(a.created_at)).slice(0,3).map(m=>`  ${m.type==='income'?'💵':'💸'} ${m.description}: $${Number(m.amount).toLocaleString()}`).join('\n');
  await sendWhatsApp(phone,
    `📊 *${planNames[mod]}*\n━━━━━━━━━━━━━━\n` +
    `💵 Ingresos: *$${inc.toLocaleString()}*\n` +
    `💸 Gastos:   *$${exp.toLocaleString()}*\n` +
    `${bal>=0?'✅':'⚠️'} Balance: *${bal>=0?'+':''}$${bal.toLocaleString()}*\n` +
    `📋 ${(movs||[]).length} movimientos\n` +
    `━━━━━━━━━━━━━━\n` +
    (topCats?`📂 *Top gastos:*\n${topCats}\n\n`:'')+
    `🕐 *Recientes:*\n${last3}\n\n` +
    `_"informe" para PDF · "menu" para más opciones_`
  );
}

// ══════════════════════════════════════
// PDF — helper reutilizable
// ══════════════════════════════════════
async function generarYEnviarPDF(phone, user, mod, titulo) {
  const planNames = {personal:'Finanzas Personales',parejas:'Finanzas en Pareja',viajes:'Viajes',comerciantes:'Mi Negocio'};
  const tit = titulo || planNames[mod] || 'Informe';
  const { data: movs } = await supabase.from('movements').select('*').eq('user_id', user.id).eq('module', mod).order('date',{ascending:false});
  const inc = (movs||[]).filter(m=>m.type==='income').reduce((s,m)=>s+Number(m.amount),0);
  const exp = (movs||[]).filter(m=>m.type==='expense').reduce((s,m)=>s+Number(m.amount),0);
  const bal = inc - exp;
  const byCat = {};
  (movs||[]).filter(m=>m.type==='expense').forEach(m=>{byCat[m.category]=(byCat[m.category]||0)+Number(m.amount);});
  const topCats = Object.entries(byCat).sort((a,b)=>b[1]-a[1]).slice(0,5).map(([c,v])=>`  • ${c}: $${v.toLocaleString()}`).join('\n');
  try {
    const fecha = new Date().toLocaleDateString('es-CO',{day:'2-digit',month:'long',year:'numeric'});
    const html = generarHTMLInforme(movs||[], tit, fecha, user.name);
    const token = crypto.randomBytes(16).toString('hex');
    await supabase.from('temp_files').insert({token, content: html, filename:`informe-${mod}.html`, expires_at: new Date(Date.now()+24*60*60*1000).toISOString()});
    const link = `https://micaja-backend-production.up.railway.app/api/download/${token}`;
    await sendWhatsApp(phone,
      `📄 *Informe: ${tit}*\n━━━━━━━━━━━━━━\n` +
      `💵 Ingresos: *$${inc.toLocaleString()}*\n` +
      `💸 Gastos:   *$${exp.toLocaleString()}*\n` +
      `${bal>=0?'✅':'⚠️'} Balance: *${bal>=0?'+':''}$${bal.toLocaleString()}*\n` +
      (topCats?`━━━━━━━━━━━━━━\n📂 Top gastos:\n${topCats}\n`:'')+
      `━━━━━━━━━━━━━━\n📥 *Descarga el informe:*\n${link}\n_Disponible 24 horas_\n\n` +
      `*0* Volver al menú`
    );
  } catch(e) {
    await sendWhatsApp(phone, `📊 *${tit}*\n💵 $${inc.toLocaleString()} ingresos\n💸 $${exp.toLocaleString()} gastos\n${bal>=0?'✅':'⚠️'} $${bal.toLocaleString()} balance\n\nError generando PDF. Intenta de nuevo.`);
  }
}

// ══════════════════════════════════════
// HELPER — parsear monto colombiano
// ══════════════════════════════════════
function parsearMonto(raw) {
  const s = raw.toLowerCase().trim();
  if (/mil|k/.test(s)) return parseFloat(s.replace(/mil|k/i,'').replace(/[.,]/g,'')) * 1000;
  if (/millon|millones|palo|palos/.test(s)) return parseFloat(s.replace(/millon.*|palo.*/i,'').replace(/[.,]/g,'')) * 1000000;
  return parseFloat(s.replace(/[.,]/g,'')) || 0;
}

// ══════════════════════════════════════
// MOSTRAR SUBMENU — cada módulo consulta DB y trae datos reales
// ══════════════════════════════════════
async function mostrarSubmenu(phone, modulo, user) {
  await setCtxByPhone(phone, { step: 'sub_' + modulo });

  switch(modulo) {

    // ── NEGOCIO ──────────────────────────────────────────────
    case 'negocio': {
      const { data: movs } = await supabase.from('movements').select('type,amount,description,date,category').eq('user_id',user.id).eq('module','comerciantes').order('date',{ascending:false});
      const inc = (movs||[]).filter(m=>m.type==='income').reduce((s,m)=>s+Number(m.amount),0);
      const exp = (movs||[]).filter(m=>m.type==='expense').reduce((s,m)=>s+Number(m.amount),0);
      const bal = inc - exp;
      const last = (movs||[]).slice(0,3).map(m=>`  ${m.type==='income'?'💵':'💸'} ${m.description} $${Number(m.amount).toLocaleString()}`).join('\n');
      await sendWhatsApp(phone,
        `🏪 *Mi Negocio*\n━━━━━━━━━━━━━━\n` +
        `Aquí registras ventas, compras de mercancía,\nnómina y todos los movimientos de tu negocio.\n` +
        `━━━━━━━━━━━━━━\n` +
        `💵 Ingresos: *$${inc.toLocaleString()}*\n` +
        `💸 Gastos:   *$${exp.toLocaleString()}*\n` +
        `${bal>=0?'✅':'⚠️'} Utilidad: *${bal>=0?'+':''}$${bal.toLocaleString()}*\n` +
        `📋 ${(movs||[]).length} movimientos\n` +
        (last?`━━━━━━━━━━━━━━\n🕐 Recientes:\n${last}\n`:``)+
        `━━━━━━━━━━━━━━\n\n` +
        `*1* 📊 Ver resumen detallado\n` +
        `*2* 💸 Registrar gasto del negocio\n` +
        `*3* 💵 Registrar venta / ingreso\n` +
        `*4* 🕐 Ver últimos movimientos\n` +
        `*5* 📄 Descargar informe PDF\n` +
        `*6* 🔄 Activar módulo negocio\n` +
        `*0* ↩ Volver al menú`
      );
      break;
    }

    // ── PAREJA ────────────────────────────────────────────────
    case 'pareja': {
      const { data: movs } = await supabase.from('movements').select('type,amount,description,date,category').eq('user_id',user.id).eq('module','parejas').order('date',{ascending:false});
      const inc = (movs||[]).filter(m=>m.type==='income').reduce((s,m)=>s+Number(m.amount),0);
      const exp = (movs||[]).filter(m=>m.type==='expense').reduce((s,m)=>s+Number(m.amount),0);
      const bal = inc - exp;
      const last = (movs||[]).slice(0,3).map(m=>`  ${m.type==='income'?'💵':'💸'} ${m.description} $${Number(m.amount).toLocaleString()}`).join('\n');
      await sendWhatsApp(phone,
        `💑 *Finanzas en Pareja*\n━━━━━━━━━━━━━━\n` +
        `Registra gastos e ingresos compartidos\ncon tu pareja para llevar las cuentas claras.\n` +
        `━━━━━━━━━━━━━━\n` +
        `💵 Ingresos: *$${inc.toLocaleString()}*\n` +
        `💸 Gastos:   *$${exp.toLocaleString()}*\n` +
        `${bal>=0?'✅':'⚠️'} Balance: *${bal>=0?'+':''}$${bal.toLocaleString()}*\n` +
        `📋 ${(movs||[]).length} movimientos\n` +
        (last?`━━━━━━━━━━━━━━\n🕐 Recientes:\n${last}\n`:``)+
        `━━━━━━━━━━━━━━\n\n` +
        `*1* 📊 Ver resumen detallado\n` +
        `*2* 💸 Registrar gasto de pareja\n` +
        `*3* 💵 Registrar ingreso compartido\n` +
        `*4* 🕐 Ver últimos movimientos\n` +
        `*5* 📄 Descargar informe PDF\n` +
        `*6* 🔄 Activar módulo pareja\n` +
        `*0* ↩ Volver al menú`
      );
      break;
    }

    // ── PERSONAL ──────────────────────────────────────────────
    case 'personal': {
      const { data: movs } = await supabase.from('movements').select('type,amount,description,date,category').eq('user_id',user.id).eq('module','personal').order('date',{ascending:false});
      const inc = (movs||[]).filter(m=>m.type==='income').reduce((s,m)=>s+Number(m.amount),0);
      const exp = (movs||[]).filter(m=>m.type==='expense').reduce((s,m)=>s+Number(m.amount),0);
      const bal = inc - exp;
      const last = (movs||[]).slice(0,3).map(m=>`  ${m.type==='income'?'💵':'💸'} ${m.description} $${Number(m.amount).toLocaleString()}`).join('\n');
      await sendWhatsApp(phone,
        `👤 *Finanzas Personales*\n━━━━━━━━━━━━━━\n` +
        `Controla tus ingresos y gastos del día a día:\narriendo, servicios, mercado, transporte y más.\n` +
        `━━━━━━━━━━━━━━\n` +
        `💵 Ingresos: *$${inc.toLocaleString()}*\n` +
        `💸 Gastos:   *$${exp.toLocaleString()}*\n` +
        `${bal>=0?'✅':'⚠️'} Balance: *${bal>=0?'+':''}$${bal.toLocaleString()}*\n` +
        `📋 ${(movs||[]).length} movimientos\n` +
        (last?`━━━━━━━━━━━━━━\n🕐 Recientes:\n${last}\n`:``)+
        `━━━━━━━━━━━━━━\n\n` +
        `*1* 📊 Ver resumen detallado\n` +
        `*2* 💸 Registrar gasto personal\n` +
        `*3* 💵 Registrar ingreso personal\n` +
        `*4* 🕐 Ver últimos movimientos\n` +
        `*5* 📄 Descargar informe PDF\n` +
        `*6* 🔄 Activar módulo personal\n` +
        `*0* ↩ Volver al menú`
      );
      break;
    }

    // ── VIAJES ────────────────────────────────────────────────
    case 'viajes': {
      const { data: trips } = await supabase.from('trips').select('*,trip_expenses(amount)').eq('user_id',user.id).order('created_at',{ascending:false}).limit(5);
      const activos = (trips||[]).filter(t=>t.status==='active');
      const totalGastos = activos[0] ? (activos[0].trip_expenses||[]).reduce((s,e)=>s+Number(e.amount),0) : 0;
      await sendWhatsApp(phone,
        `✈️ *Viajes*\n━━━━━━━━━━━━━━\n` +
        `Divide los gastos del viaje entre el grupo\ny ve quién debe pagarle a quién al final.\n` +
        `━━━━━━━━━━━━━━\n` +
        `📋 Total viajes: *${(trips||[]).length}*\n` +
        `🟢 Activos: *${activos.length}*\n` +
        (activos[0]?`✈️ Activo: *${activos[0].name}*\n💰 Gastado: *$${totalGastos.toLocaleString()}*\n`:``)+
        `━━━━━━━━━━━━━━\n\n` +
        `*1* 📋 Ver mis viajes\n` +
        `*2* 💰 Ver gastos del viaje activo\n` +
        `*3* ➕ Crear nuevo viaje\n` +
        `*4* 📄 Descargar informe PDF\n` +
        `*0* ↩ Volver al menú`
      );
      break;
    }

    // ── DEUDAS ────────────────────────────────────────────────
    case 'deudas': {
      const { data: deudas } = await supabase.from('debts').select('*').eq('user_id',user.id).neq('status','paid');
      const meDeben = (deudas||[]).filter(d=>d.type==='me_deben');
      const yoDebo  = (deudas||[]).filter(d=>d.type==='debo');
      const totalMD = meDeben.reduce((s,d)=>s+Number(d.amount)-(Number(d.paid)||0),0);
      const totalYD = yoDebo.reduce((s,d)=>s+Number(d.amount)-(Number(d.paid)||0),0);
      const listaMD = meDeben.slice(0,3).map(d=>{const p=Number(d.amount)-(Number(d.paid)||0);return `  👤 ${d.person_name}: $${p.toLocaleString()}`;}).join('\n');
      const listaYD = yoDebo.slice(0,3).map(d=>{const p=Number(d.amount)-(Number(d.paid)||0);return `  👤 ${d.person_name}: $${p.toLocaleString()}`;}).join('\n');
      await sendWhatsApp(phone,
        `💸 *Deudas*\n━━━━━━━━━━━━━━\n` +
        `Lleva el control de lo que debes y\nlo que te deben para nunca olvidar nada.\n` +
        `━━━━━━━━━━━━━━\n` +
        `💰 Me deben: *$${totalMD.toLocaleString()}* (${meDeben.length} deudas)\n` +
        `💳 Yo debo:  *$${totalYD.toLocaleString()}* (${yoDebo.length} deudas)\n` +
        `${totalMD>=totalYD?'✅':'⚠️'} Balance: *${totalMD>=totalYD?'+':''}$${(totalMD-totalYD).toLocaleString()}*\n` +
        (listaMD?`━━━━━━━━━━━━━━\n💰 Me deben:\n${listaMD}\n`:``)+
        (listaYD?`💳 Yo debo:\n${listaYD}\n`:``)+
        `━━━━━━━━━━━━━━\n\n` +
        `*1* 💰 Ver quién me debe\n` +
        `*2* 💳 Ver a quién le debo\n` +
        `*3* ➕ Registrar nueva deuda\n` +
        `*4* 📄 Descargar informe PDF\n` +
        `*0* ↩ Volver al menú`
      );
      break;
    }

    // ── MÉTODOS DE PAGO ──────────────────────────────────────
    case 'pagos': {
      const { data: cfg } = await supabase.from('user_configs').select('*').eq('user_id',user.id).single();
      const tieneAlgo = cfg?.nequi || cfg?.bancolombia || cfg?.daviplata || cfg?.otro_pago;
      await sendWhatsApp(phone,
        `💳 *Métodos de pago*\n━━━━━━━━━━━━━━\n` +
        `Guarda tus datos para recibir pagos:\nNequi, Bancolombia, Daviplata y más.\n` +
        `━━━━━━━━━━━━━━\n` +
        `${cfg?.nequi      ? `📱 Nequi:       *${cfg.nequi}*\n`      : `📱 Nequi:       _no configurado_\n`}` +
        `${cfg?.daviplata  ? `📱 Daviplata:   *${cfg.daviplata}*\n`  : ``}` +
        `${cfg?.bancolombia? `🏦 Bancolombia: *${cfg.bancolombia}*\n`: `🏦 Bancolombia: _no configurado_\n`}` +
        `${cfg?.otro_pago  ? `💰 Otro:        *${cfg.otro_pago}*\n`  : ``}` +
        `━━━━━━━━━━━━━━\n\n` +
        `*1* 👁 Ver mis datos\n` +
        `*2* 📱 Guardar / actualizar Nequi\n` +
        `*3* 🏦 Guardar / actualizar Bancolombia\n` +
        `*4* 📱 Guardar / actualizar Daviplata\n` +
        `*0* ↩ Volver al menú`
      );
      break;
    }

    // ── MERCADO ───────────────────────────────────────────────
    case 'mercado': {
      const { data: items } = await supabase.from('mercado').select('*').eq('user_id',user.id).eq('done',false).order('categoria');
      const total = (items||[]).length;
      const porCat = {};
      (items||[]).forEach(i=>{ const c=i.categoria||'Otros'; porCat[c]=(porCat[c]||[]).concat(i); });
      let lista = '';
      Object.keys(porCat).forEach(cat=>{ lista+=`\n*${cat}:*\n`; porCat[cat].slice(0,5).forEach(i=>{ lista+=`  ☐ ${i.nombre}${i.cantidad?' ('+i.cantidad+')':''}\n`; }); if(porCat[cat].length>5) lista+=`  _...y ${porCat[cat].length-5} más_\n`; });
      await sendWhatsApp(phone,
        `🛒 *Lista de mercado (${total} productos)*\n━━━━━━━━━━━━━━\n` +
        `Tu lista de compras pendientes por categoría.\n` +
        (total ? lista : `\n🎉 ¡Lista vacía! No hay productos pendientes.\n`)+
        `━━━━━━━━━━━━━━\n\n` +
        `*1* 📋 Ver lista completa\n` +
        `*2* ➕ Agregar producto\n` +
        `*0* ↩ Volver al menú`
      );
      break;
    }

    // ── TAREAS ────────────────────────────────────────────────
    case 'tareas': {
      const { data: tareas } = await supabase.from('tasks').select('*').eq('user_id',user.id).eq('done',false).order('created_at',{ascending:false});
      const total = (tareas||[]).length;
      const alta  = (tareas||[]).filter(t=>t.prioridad==='alta').length;
      const priIcon = {alta:'🔴',media:'🟡',baja:'🔵'};
      let lista = (tareas||[]).slice(0,7).map(t=>`  ${priIcon[t.prioridad]||'⚪'} ${t.titulo}${t.fecha?' ('+t.fecha+')':''}`).join('\n');
      if(total>7) lista += `\n  _...y ${total-7} más_`;
      await sendWhatsApp(phone,
        `✅ *Tareas pendientes (${total})*\n━━━━━━━━━━━━━━\n` +
        `Tus pendientes y recordatorios ordenados\npor prioridad.\n` +
        `━━━━━━━━━━━━━━\n` +
        `🔴 Alta: *${alta}* · Total: *${total}*\n` +
        (lista ? `\n${lista}\n` : `\n🎉 ¡Sin tareas pendientes!\n`) +
        `━━━━━━━━━━━━━━\n\n` +
        `*1* 📋 Ver todas las tareas\n` +
        `*2* ➕ Agregar tarea\n` +
        `*0* ↩ Volver al menú`
      );
      break;
    }

    // ── SERVICIOS ─────────────────────────────────────────────
    case 'servicios': {
      const { data: servs } = await supabase.from('servicios').select('*').eq('user_id',user.id).order('dia');
      const diaHoy = new Date().getDate();
      const vencidos = (servs||[]).filter(s=>!s.pagado_mes && s.dia < diaHoy);
      const proximos = (servs||[]).filter(s=>!s.pagado_mes && s.dia >= diaHoy && s.dia-diaHoy <= 5);
      const pagados  = (servs||[]).filter(s=>s.pagado_mes);
      const pendientes = (servs||[]).filter(s=>!s.pagado_mes && s.dia-diaHoy > 5);
      let lista = '';
      if(vencidos.length)  lista+=`\n⚠️ *Vencidos (${vencidos.length}):*\n`+vencidos.map(s=>`  ${s.icono} ${s.nombre} — venció día ${s.dia}`).join('\n');
      if(proximos.length)  lista+=`\n📅 *Próximos ${proximos.length===1?'(hoy)':'(<5 días)'}:*\n`+proximos.map(s=>{const d=s.dia-diaHoy;return `  ${s.icono} ${s.nombre} — ${d===0?'HOY':'en '+d+' día'+(d!==1?'s':'')}`}).join('\n');
      if(pagados.length)   lista+=`\n✅ *Pagados este mes (${pagados.length}):*\n`+pagados.map(s=>`  ${s.icono} ${s.nombre}`).join('\n');
      if(pendientes.length)lista+=`\n🟢 *Pendientes:*\n`+pendientes.slice(0,4).map(s=>`  ${s.icono} ${s.nombre} — día ${s.dia}`).join('\n');
      await sendWhatsApp(phone,
        `🔔 *Servicios y pagos (${(servs||[]).length})*\n━━━━━━━━━━━━━━\n` +
        `Tus servicios públicos y pagos del mes\ncon fechas de vencimiento y estado.\n` +
        `━━━━━━━━━━━━━━\n` +
        `⚠️ Vencidos: *${vencidos.length}* · 📅 Próximos: *${proximos.length}* · ✅ Pagados: *${pagados.length}*` +
        (lista || `\n\n🎉 Todo al día!`) +
        `\n━━━━━━━━━━━━━━\n\n` +
        `*1* 📋 Ver todos los servicios\n` +
        `*2* ✅ Marcar servicio como pagado\n` +
        `*0* ↩ Volver al menú`
      );
      break;
    }

    // ── INFORMES ──────────────────────────────────────────────
    case 'informes': {
      await sendWhatsApp(phone,
        `📊 *Informes PDF*\n━━━━━━━━━━━━━━\n` +
        `Genera informes descargables de tus finanzas,\nigual al diseño de la web. Disponibles 24 horas.\n` +
        `━━━━━━━━━━━━━━\n\n` +
        `*1* 📄 Informe del mes actual\n` +
        `*2* 📄 Histórico completo (módulo activo)\n` +
        `*3* 📄 Finanzas Personales\n` +
        `*4* 📄 Mi Negocio\n` +
        `*5* 📄 Finanzas en Pareja\n` +
        `*0* ↩ Volver al menú`
      );
      break;
    }

    // ── MÓDULO ────────────────────────────────────────────────
    case 'modulo': {
      const planNames = {personal:'👤 Personal',parejas:'💑 Pareja',viajes:'✈️ Viajes',comerciantes:'🏪 Negocio'};
      const actual = planNames[user.plan] || '👤 Personal';
      await sendWhatsApp(phone,
        `📋 *Cambiar módulo activo*\n━━━━━━━━━━━━━━\n` +
        `Módulo actual: *${actual}*\n\n` +
        `*1* 👤 Personal — finanzas del día a día\n` +
        `*2* 🏪 Negocio — ventas y gastos del negocio\n` +
        `*3* 💑 Pareja — gastos compartidos\n` +
        `*4* ✈️ Viajes — gastos de un viaje\n\n` +
        `*0* ↩ Volver al menú`
      );
      break;
    }
  }
}

// ══════════════════════════════════════
// MANEJAR OPCIONES DENTRO DE SUBMENÚ
// ══════════════════════════════════════
async function manejarSubmenu(phone, modulo, lower, textOriginal, user, ctx) {
  const planNames = {personal:'👤 Personal',parejas:'💑 Pareja',viajes:'✈️ Viajes',comerciantes:'🏪 Negocio'};

  switch(modulo) {

    // ── NEGOCIO / PAREJA / PERSONAL ───────────────────────────
    case 'negocio':
    case 'pareja':
    case 'personal': {
      const mod   = modulo==='pareja'?'parejas':modulo==='negocio'?'comerciantes':'personal';
      const titulo= {negocio:'Mi Negocio',pareja:'Finanzas en Pareja',personal:'Finanzas Personales'}[modulo];

      if (lower==='1') {
        await enviarResumen(phone, user, mod);
        await sendWhatsApp(phone, `*5* 📄 PDF | *0* ↩ Menú`);

      } else if (lower==='2') {
        await setCtxByPhone(phone, {step:`sub_${modulo}`, esperando:'gasto', modulo:mod});
        await sendWhatsApp(phone, `💸 Escribe el gasto:\n_"pagué mercado 150mil"_\n\n*0* Cancelar`);

      } else if (lower==='3') {
        await setCtxByPhone(phone, {step:`sub_${modulo}`, esperando:'ingreso', modulo:mod});
        await sendWhatsApp(phone, `💵 Escribe el ingreso:\n_"me ingresaron 2 millones"_\n\n*0* Cancelar`);

      } else if (lower==='4') {
        const { data: movs } = await supabase.from('movements').select('*').eq('user_id',user.id).eq('module',mod).order('date',{ascending:false}).limit(8);
        const lista = (movs||[]).map(m=>`${m.type==='income'?'💵':'💸'} ${m.description} $${Number(m.amount).toLocaleString()} (${m.date})`).join('\n');
        await sendWhatsApp(phone, `🕐 *Últimos movimientos — ${titulo}*\n━━━━━━━━━━━━━━\n${lista||'Sin movimientos aún'}\n\n*5* 📄 PDF | *0* ↩ Menú`);

      } else if (lower==='5') {
        await generarYEnviarPDF(phone, user, mod, titulo);

      } else if (lower==='6') {
        await supabase.from('users').update({plan:mod}).eq('id', user.id);
        await setCtxByPhone(phone, {});
        await sendWhatsApp(phone, `✅ Módulo activo: *${planNames[mod]}* 💪\n\nEscribe *menu* para continuar`);

      } else if (ctx.esperando==='gasto' || ctx.esperando==='ingreso') {
        const parsed = await parseWithAI(lower, user.name, ctx.modulo||user.plan);
        if (parsed) {
          await setCtxByPhone(phone, {step:`sub_${modulo}`, step2:'confirm_submenu', type:parsed.type, amount:parsed.amount, description:parsed.description, category:parsed.category, modulo:ctx.modulo||user.plan});
          await sendWhatsApp(phone, `${parsed.type==='income'?'💵':'💸'} *${parsed.description}*\n$${Number(parsed.amount).toLocaleString()} COP — ${parsed.category}\n\n*sí* guardar | *no* cancelar`);
        } else {
          await sendWhatsApp(phone, `No entendí el monto. Escríbelo así:\n_"pagué mercado 50mil"_\n\n*0* Cancelar`);
        }

      } else if (ctx.step2==='confirm_submenu') {
        if (['si','sí','ok','dale','listo'].includes(lower)) {
          await supabase.from('movements').insert({user_id:user.id, type:ctx.type, amount:ctx.amount, description:ctx.description, category:ctx.category, source:'whatsapp', module:ctx.modulo||user.plan});
          await setCtxByPhone(phone, {step:`sub_${modulo}`});
          const { data: movs } = await supabase.from('movements').select('type,amount').eq('user_id',user.id).eq('module',ctx.modulo||user.plan);
          const bal = (movs||[]).reduce((s,m)=>s+(m.type==='income'?Number(m.amount):-Number(m.amount)),0);
          await sendWhatsApp(phone, `✅ *Guardado!*\n${ctx.type==='income'?'💵':'💸'} ${ctx.description} — $${Number(ctx.amount).toLocaleString()}\nBalance: *${bal>=0?'+':''}$${bal.toLocaleString()}*\n\n*1* Resumen | *5* PDF | *0* Menú`);
        } else {
          await setCtxByPhone(phone, {step:`sub_${modulo}`});
          await sendWhatsApp(phone, `❌ Cancelado.\n\n*0* Menú`);
        }

      } else {
        await mostrarSubmenu(phone, modulo, user);
      }
      break;
    }

    // ── VIAJES ────────────────────────────────────────────────
    case 'viajes': {
      if (lower==='1') {
        const { data: trips } = await supabase.from('trips').select('*,trip_expenses(amount)').eq('user_id',user.id).order('created_at',{ascending:false}).limit(10);
        if (!trips||!trips.length) { await sendWhatsApp(phone, `No tienes viajes registrados.\n\n_Créalos en: milkomercios.in/MiCaja/viajes.html_\n\n*0* Menú`); return; }
        const lista = trips.map((t,i)=>{
          const total = (t.trip_expenses||[]).reduce((s,e)=>s+Number(e.amount),0);
          return `${i+1}. ${t.status==='active'?'🟢':'⚫'} *${t.name}* — $${total.toLocaleString()} (${t.status==='active'?'activo':'finalizado'})`;
        }).join('\n');
        await sendWhatsApp(phone, `✈️ *Mis viajes*\n━━━━━━━━━━━━━━\n${lista}\n\n*0* Menú`);

      } else if (lower==='2') {
        const { data: trips } = await supabase.from('trips').select('*,trip_expenses(*),trip_members(*)').eq('user_id',user.id).eq('status','active').order('created_at',{ascending:false}).limit(1);
        const trip = trips?.[0];
        if (!trip) { await sendWhatsApp(phone, `No tienes un viaje activo.\n\n*0* Menú`); return; }
        const exps = (trip.trip_expenses||[]);
        const total = exps.reduce((s,e)=>s+Number(e.amount),0);
        const lista = exps.slice(0,8).map(e=>`  💰 ${e.description}: $${Number(e.amount).toLocaleString()} (${e.payer})`).join('\n');
        await sendWhatsApp(phone, `✈️ *${trip.name}*\n━━━━━━━━━━━━━━\n💰 Total gastado: *$${total.toLocaleString()}*\n👥 Participantes: *${(trip.trip_members||[]).length}*\n━━━━━━━━━━━━━━\n${lista||'Sin gastos aún'}\n\n*4* PDF | *0* Menú`);

      } else if (lower==='4') {
        const { data: trips } = await supabase.from('trips').select('*,trip_expenses(*)').eq('user_id',user.id).eq('status','active').order('created_at',{ascending:false}).limit(1);
        const trip = trips?.[0];
        const movs = trip ? (trip.trip_expenses||[]).map(e=>({type:'expense',amount:e.amount,description:e.description,category:'Viaje',date:e.expense_date||e.created_at?.split('T')[0]})) : [];
        await generarYEnviarPDF(phone, user, 'viajes', trip?`Viaje: ${trip.name}`:'Viajes');

      } else {
        await mostrarSubmenu(phone, 'viajes', user);
      }
      break;
    }

    // ── DEUDAS ────────────────────────────────────────────────
    case 'deudas': {
      if (lower==='1') {
        const { data: d } = await supabase.from('debts').select('*').eq('user_id',user.id).neq('status','paid').eq('type','me_deben').order('created_at',{ascending:false});
        if (!d||!d.length) { await sendWhatsApp(phone, `💰 ¡Nadie te debe nada! 🎉\n\n*0* Menú`); return; }
        const totalMD = d.reduce((s,x)=>s+Number(x.amount)-(Number(x.paid)||0),0);
        const lista = d.map(x=>{const p=Number(x.amount)-(Number(x.paid)||0);return `👤 *${x.person_name}*: $${p.toLocaleString()}${x.description?' — '+x.description:''}`;}).join('\n');
        await sendWhatsApp(phone, `💰 *Me deben en total: $${totalMD.toLocaleString()}*\n━━━━━━━━━━━━━━\n${lista}\n\n*4* PDF | *0* Menú`);

      } else if (lower==='2') {
        const { data: d } = await supabase.from('debts').select('*').eq('user_id',user.id).neq('status','paid').eq('type','debo').order('created_at',{ascending:false});
        if (!d||!d.length) { await sendWhatsApp(phone, `💳 ¡No debes nada! 🎉\n\n*0* Menú`); return; }
        const totalYD = d.reduce((s,x)=>s+Number(x.amount)-(Number(x.paid)||0),0);
        const lista = d.map(x=>{const p=Number(x.amount)-(Number(x.paid)||0);return `👤 *${x.person_name}*: $${p.toLocaleString()}${x.description?' — '+x.description:''}`;}).join('\n');
        await sendWhatsApp(phone, `💳 *Yo debo en total: $${totalYD.toLocaleString()}*\n━━━━━━━━━━━━━━\n${lista}\n\n*4* PDF | *0* Menú`);

      } else if (lower==='3') {
        await setCtxByPhone(phone, {step:'sub_deudas', esperando:'nueva_deuda'});
        await sendWhatsApp(phone, `Registra la deuda:\n_"le debo 200k a Juan"_\n_"Pedro me debe 500mil"_\n\n*0* Cancelar`);

      } else if (lower==='4') {
        const { data: deudas } = await supabase.from('debts').select('*').eq('user_id',user.id).neq('status','paid');
        const meDeben = (deudas||[]).filter(d=>d.type==='me_deben');
        const yoDebo  = (deudas||[]).filter(d=>d.type==='debo');
        const totalMD = meDeben.reduce((s,d)=>s+Number(d.amount)-(Number(d.paid)||0),0);
        const totalYD = yoDebo.reduce((s,d)=>s+Number(d.amount)-(Number(d.paid)||0),0);
        const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Deudas</title><style>body{font-family:Segoe UI,sans-serif;padding:28px;color:#0F172A}h1{font-size:20px;font-weight:800;margin-bottom:3px}.sub{color:#64748B;font-size:12px;margin-bottom:18px}.cards{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:18px}.card{border-radius:10px;padding:14px;text-align:center}.val{font-size:18px;font-weight:800;margin:4px 0}.lbl{font-size:11px;color:#64748B}.sec h3{font-size:13px;font-weight:700;margin:14px 0 8px;border-bottom:2px solid #E2E8F0;padding-bottom:4px}.row{display:flex;gap:8px;padding:5px 0;border-bottom:1px solid #F8FAFC;font-size:11px}.footer{margin-top:20px;font-size:10px;color:#94A3B8;text-align:center;border-top:1px solid #E2E8F0;padding-top:10px}</style></head><body><h1>Deudas</h1><div class="sub">${new Date().toLocaleDateString('es-CO',{day:'2-digit',month:'long',year:'numeric'})} — ${user.name||''}</div><div class="cards"><div class="card" style="background:#ECFDF5;border:1px solid #6EE7B7"><div class="val" style="color:#059669">$${totalMD.toLocaleString()}</div><div class="lbl">Me deben</div></div><div class="card" style="background:#FEF2F2;border:1px solid #FCA5A5"><div class="val" style="color:#EF4444">$${totalYD.toLocaleString()}</div><div class="lbl">Yo debo</div></div><div class="card" style="background:${totalMD>=totalYD?'#EFF6FF':'#FEF2F2'};border:1px solid ${totalMD>=totalYD?'#93C5FD':'#FCA5A5'}"><div class="val" style="color:${totalMD>=totalYD?'#2563EB':'#EF4444'}">${totalMD>=totalYD?'+':''}$${(totalMD-totalYD).toLocaleString()}</div><div class="lbl">Balance</div></div></div><div class="sec"><h3>Me deben</h3>${meDeben.map(d=>{const p=Number(d.amount)-(Number(d.paid)||0);return `<div class="row"><span style="flex:1;font-weight:600">${d.person_name}</span><span style="color:#64748B">${d.description||''}</span><span style="font-weight:700;color:#059669">$${p.toLocaleString()}</span></div>`;}).join('')||'<p style="color:#94A3B8;font-size:11px">Ninguna</p>'}</div><div class="sec"><h3>Yo debo</h3>${yoDebo.map(d=>{const p=Number(d.amount)-(Number(d.paid)||0);return `<div class="row"><span style="flex:1;font-weight:600">${d.person_name}</span><span style="color:#64748B">${d.description||''}</span><span style="font-weight:700;color:#EF4444">$${p.toLocaleString()}</span></div>`;}).join('')||'<p style="color:#94A3B8;font-size:11px">Ninguna</p>'}</div><div class="footer">MiCaja — milkomercios.in/MiCaja</div></body></html>`;
        const token = crypto.randomBytes(16).toString('hex');
        await supabase.from('temp_files').insert({token, content:html, filename:'deudas.html', expires_at:new Date(Date.now()+24*60*60*1000).toISOString()});
        await sendWhatsApp(phone, `📄 *Informe Deudas*\n\n📥 https://micaja-backend-production.up.railway.app/api/download/${token}\n_Disponible 24 horas_\n\n*0* Menú`);

      } else if (ctx.esperando==='nueva_deuda') {
        // Detectar si es "le debo X a Y" o "Y me debe X"
        const dMatch = lower.match(/(?:le debo|debo)\s+(\S+)\s+a\s+(.+)/i);
        const mMatch = lower.match(/(.+?)\s+me debe\s+(\S+)/i);
        if (dMatch) {
          const amount = parsearMonto(dMatch[1]); const persona = dMatch[2].trim();
          await supabase.from('debts').insert({user_id:user.id, type:'debo', person_name:persona, amount, status:'pending', paid:0});
          await setCtxByPhone(phone, {step:'sub_deudas'});
          await sendWhatsApp(phone, `✅ Registrado: le debes *$${amount.toLocaleString()}* a *${persona}*\n\n*0* Menú`);
        } else if (mMatch) {
          const persona = mMatch[1].trim(); const amount = parsearMonto(mMatch[2]);
          await supabase.from('debts').insert({user_id:user.id, type:'me_deben', person_name:persona, amount, status:'pending', paid:0});
          await setCtxByPhone(phone, {step:'sub_deudas'});
          await sendWhatsApp(phone, `✅ Registrado: *${persona}* te debe *$${amount.toLocaleString()}*\n\n*0* Menú`);
        } else {
          await sendWhatsApp(phone, `No entendí. Escríbelo así:\n_"le debo 200k a Juan"_\n_"Pedro me debe 500mil"_\n\n*0* Cancelar`);
        }

      } else {
        await mostrarSubmenu(phone, 'deudas', user);
      }
      break;
    }

    // ── MÉTODOS DE PAGO ──────────────────────────────────────
    case 'pagos': {
      if (lower==='1') {
        const { data: cfg } = await supabase.from('user_configs').select('*').eq('user_id',user.id).single();
        await sendWhatsApp(phone,
          `💳 *Tus datos de pago*\n━━━━━━━━━━━━━━\n` +
          `${cfg?.nequi      ?`📱 Nequi:       *${cfg.nequi}*\n`      :`📱 Nequi:       _no guardado_\n`}` +
          `${cfg?.daviplata  ?`📱 Daviplata:   *${cfg.daviplata}*\n`  :``}` +
          `${cfg?.bancolombia?`🏦 Bancolombia: *${cfg.bancolombia}*\n`:`🏦 Bancolombia: _no guardado_\n`}` +
          `${cfg?.otro_pago  ?`💰 Otro:        *${cfg.otro_pago}*\n`  :``}\n*0* Menú`
        );
      } else if (['2','3','4'].includes(lower)) {
        const tipoMap  = {'2':'nequi','3':'bancol','4':'daviplata'};
        const nombreMap= {'2':'Nequi','3':'Bancolombia','4':'Daviplata'};
        await setCtxByPhone(phone, {step:'sub_pagos', esperando:tipoMap[lower]});
        await sendWhatsApp(phone, `Escribe tu número de ${nombreMap[lower]}:\n_Ej: 3001234567_\n\n*0* Cancelar`);
      } else if (ctx.esperando) {
        const updates = {user_id:user.id};
        if(ctx.esperando==='nequi')    updates.nequi       = lower.replace(/\s+/g,'');
        if(ctx.esperando==='bancol')   updates.bancolombia = lower.replace(/\s+/g,'');
        if(ctx.esperando==='daviplata')updates.daviplata   = lower.replace(/\s+/g,'');
        await supabase.from('user_configs').upsert(updates, {onConflict:'user_id'});
        const nombre = {nequi:'Nequi',bancol:'Bancolombia',daviplata:'Daviplata'}[ctx.esperando];
        await setCtxByPhone(phone, {step:'sub_pagos'});
        await sendWhatsApp(phone, `✅ *${nombre}* guardado!\n\n*1* Ver datos | *0* Menú`);
      } else {
        await mostrarSubmenu(phone, 'pagos', user);
      }
      break;
    }

    // ── MERCADO ───────────────────────────────────────────────
    case 'mercado': {
      if (lower==='1') {
        const { data: items } = await supabase.from('mercado').select('*').eq('user_id',user.id).eq('done',false).order('categoria');
        if (!items||!items.length) { await sendWhatsApp(phone, `🛒 Lista vacía! 🎉\n\n*0* Menú`); return; }
        const porCat = {};
        items.forEach(i=>{ const c=i.categoria||'Otros'; porCat[c]=(porCat[c]||[]).concat(i); });
        let msg = `🛒 *Lista completa (${items.length})*\n━━━━━━━━━━━━━━\n`;
        Object.keys(porCat).forEach(cat=>{ msg+=`\n*${cat}:*\n`; porCat[cat].forEach(i=>{ msg+=`  ☐ ${i.nombre}${i.cantidad?' ('+i.cantidad+')':''}\n`; }); });
        await sendWhatsApp(phone, msg+`\n*0* Menú`);

      } else if (lower==='2') {
        await setCtxByPhone(phone, {step:'sub_mercado', esperando:'item_mercado'});
        await sendWhatsApp(phone, `¿Qué producto necesitas?\n_"leche 2 litros"_\n\n*0* Cancelar`);

      } else if (ctx.esperando==='item_mercado') {
        await supabase.from('mercado').insert({user_id:user.id, nombre:textOriginal.trim(), cantidad:null, categoria:'Otros', done:false});
        await setCtxByPhone(phone, {step:'sub_mercado'});
        await sendWhatsApp(phone, `✅ *${textOriginal.trim()}* agregado!\n\n*1* Ver lista | *2* Agregar otro | *0* Menú`);

      } else {
        await mostrarSubmenu(phone, 'mercado', user);
      }
      break;
    }

    // ── TAREAS ────────────────────────────────────────────────
    case 'tareas': {
      if (lower==='1') {
        const { data: tareas } = await supabase.from('tasks').select('*').eq('user_id',user.id).eq('done',false).order('created_at',{ascending:false});
        if (!tareas||!tareas.length) { await sendWhatsApp(phone, `✅ Sin tareas pendientes! 🎉\n\n*0* Menú`); return; }
        const priIcon = {alta:'🔴',media:'🟡',baja:'🔵'};
        const lista = tareas.map(t=>`${priIcon[t.prioridad]||'⚪'} ${t.titulo}${t.fecha?' ('+t.fecha+')':''}`).join('\n');
        await sendWhatsApp(phone, `✅ *Todas las tareas (${tareas.length})*\n━━━━━━━━━━━━━━\n${lista}\n\n*0* Menú`);

      } else if (lower==='2') {
        await setCtxByPhone(phone, {step:'sub_tareas', esperando:'nueva_tarea'});
        await sendWhatsApp(phone, `Escribe la tarea:\n_"llamar al banco"_\n\n*0* Cancelar`);

      } else if (ctx.esperando==='nueva_tarea') {
        await supabase.from('tasks').insert({user_id:user.id, titulo:textOriginal.trim(), prioridad:'media', done:false});
        await setCtxByPhone(phone, {step:'sub_tareas'});
        await sendWhatsApp(phone, `✅ *${textOriginal.trim()}* agregada!\n\n*1* Ver tareas | *2* Otra | *0* Menú`);

      } else {
        await mostrarSubmenu(phone, 'tareas', user);
      }
      break;
    }

    // ── SERVICIOS ─────────────────────────────────────────────
    case 'servicios': {
      if (lower==='1') {
        const { data: servs } = await supabase.from('servicios').select('*').eq('user_id',user.id).order('dia');
        if (!servs||!servs.length) { await sendWhatsApp(phone, `🔔 Sin servicios configurados.\n\nConfigura en: milkomercios.in/MiCaja/servicios.html\n\n*0* Menú`); return; }
        const diaHoy = new Date().getDate();
        const lista = servs.map(s=>{
          if(s.pagado_mes) return `✅ ${s.icono} ${s.nombre}`;
          const diff = s.dia - diaHoy;
          if(diff < 0)  return `⚠️ ${s.icono} ${s.nombre} (venció día ${s.dia})`;
          if(diff === 0)return `🔴 ${s.icono} ${s.nombre} (HOY)`;
          if(diff <= 3) return `🟡 ${s.icono} ${s.nombre} (en ${diff}d)`;
          return      `🟢 ${s.icono} ${s.nombre} (día ${s.dia})`;
        }).join('\n');
        await sendWhatsApp(phone, `🔔 *Todos los servicios:*\n━━━━━━━━━━━━━━\n${lista}\n\n*0* Menú`);

      } else if (lower==='2') {
        const { data: servs } = await supabase.from('servicios').select('*').eq('user_id',user.id).eq('pagado_mes',false).order('dia');
        if (!servs||!servs.length) { await sendWhatsApp(phone, `✅ Todo pagado este mes! 🎉\n\n*0* Menú`); return; }
        await setCtxByPhone(phone, {step:'sub_servicios', esperando:'marcar_pagado', ids:JSON.stringify(servs.map(s=>s.id))});
        await sendWhatsApp(phone, `¿Cuál marcas como pagado?\n\n`+servs.map((s,i)=>`*${i+1}* ${s.icono} ${s.nombre}`).join('\n')+`\n\n*0* Cancelar`);

      } else if (ctx.esperando==='marcar_pagado') {
        const ids = JSON.parse(ctx.ids||'[]');
        const idx = parseInt(lower)-1;
        if (idx>=0 && idx<ids.length) {
          await supabase.from('servicios').update({pagado_mes:true}).eq('id',ids[idx]);
          await setCtxByPhone(phone, {step:'sub_servicios'});
          await sendWhatsApp(phone, `✅ Marcado como pagado!\n\n*1* Ver servicios | *0* Menú`);
        } else {
          await sendWhatsApp(phone, `Número inválido. Intenta de nuevo.`);
        }

      } else {
        await mostrarSubmenu(phone, 'servicios', user);
      }
      break;
    }

    // ── INFORMES ──────────────────────────────────────────────
    case 'informes': {
      const config = {
        '1': { mod: user.plan,       titulo: 'Mes actual',          soloMes: true  },
        '2': { mod: user.plan,       titulo: 'Histórico completo',  soloMes: false },
        '3': { mod: 'personal',      titulo: 'Finanzas Personales', soloMes: false },
        '4': { mod: 'comerciantes',  titulo: 'Mi Negocio',          soloMes: false },
        '5': { mod: 'parejas',       titulo: 'Finanzas en Pareja',  soloMes: false },
      };
      if (config[lower]) {
        const { mod, titulo, soloMes } = config[lower];
        let query = supabase.from('movements').select('*').eq('user_id',user.id).eq('module',mod).order('date',{ascending:false});
        if (soloMes) { const a=new Date(); query=query.gte('date',`${a.getFullYear()}-${String(a.getMonth()+1).padStart(2,'0')}-01`); }
        const { data: movs } = await query;
        const inc = (movs||[]).filter(m=>m.type==='income').reduce((s,m)=>s+Number(m.amount),0);
        const exp = (movs||[]).filter(m=>m.type==='expense').reduce((s,m)=>s+Number(m.amount),0);
        const fecha = new Date().toLocaleDateString('es-CO',{day:'2-digit',month:'long',year:'numeric'});
        const html  = generarHTMLInforme(movs||[], titulo, fecha, user.name);
        const token = crypto.randomBytes(16).toString('hex');
        await supabase.from('temp_files').insert({token, content:html, filename:`informe.html`, expires_at:new Date(Date.now()+24*60*60*1000).toISOString()});
        await sendWhatsApp(phone,
          `📄 *${titulo}*\n━━━━━━━━━━━━━━\n` +
          `💵 $${inc.toLocaleString()} ingresos\n` +
          `💸 $${exp.toLocaleString()} gastos\n` +
          `${(inc-exp)>=0?'✅':'⚠️'} $${(inc-exp).toLocaleString()} balance\n` +
          `━━━━━━━━━━━━━━\n` +
          `📥 https://micaja-backend-production.up.railway.app/api/download/${token}\n` +
          `_Disponible 24 horas_\n\n*0* Menú`
        );
      } else {
        await mostrarSubmenu(phone, 'informes', user);
      }
      break;
    }

    // ── MÓDULO ────────────────────────────────────────────────
    case 'modulo': {
      const opMap = {'1':'personal','2':'comerciantes','3':'parejas','4':'viajes'};
      const plan = opMap[lower];
      if (plan) {
        await supabase.from('users').update({plan}).eq('id', user.id);
        await setCtxByPhone(phone, {});
        await sendWhatsApp(phone, `✅ Módulo activo: *${planNames[plan]}* 💪\n\nEscribe *menu* para continuar`);
      } else {
        await mostrarSubmenu(phone, 'modulo', user);
      }
      break;
    }

    default:
      await setCtxByPhone(phone, {});
      await sendWhatsApp(phone, `Escribe *menu* 😊`);
  }
}

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
