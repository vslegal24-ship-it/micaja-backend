// ══════════════════════════════════════
// MiCaja Backend — server.js v2
// API REST + WhatsApp Webhook
// ══════════════════════════════════════

const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const axios = require('axios');

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

// ══════ HEALTH CHECK ══════
app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'MiCaja Backend', version: '2.0.0', timestamp: new Date().toISOString() });
});

// Función para normalizar teléfono colombiano — siempre 57XXXXXXXXXX
function normalizePhone(phone) {
  let p = phone.replace(/[\s\-\+\(\)]/g, ''); // quitar espacios, guiones, +, paréntesis
  if (p.startsWith('57') && p.length === 12) return p; // ya tiene 57
  if (p.length === 10 && p.startsWith('3')) return '57' + p; // colombiano sin código
  if (p.startsWith('0057')) return p.slice(2); // 0057...
  return p; // devolver como está si no encaja
}

// ══════ AUTH ══════
app.post('/api/auth/register', async (req, res) => {
  try {
    const { phone: rawPhone, name, pin, plan, partner_phone, partner_name, business_name } = req.body;
    if (!rawPhone || !pin || pin.length !== 4) return res.status(400).json({ error: 'Teléfono y PIN de 4 dígitos requeridos' });
    const phone = normalizePhone(rawPhone);
    const { data: existing } = await supabase.from('users').select('id').eq('phone', phone).single();
    if (existing) return res.status(409).json({ error: 'Este número ya tiene cuenta' });

    // Generar código de verificación de 6 dígitos
    const verifyCode = String(Math.floor(100000 + Math.random() * 900000));
    const verifyExpiry = Date.now() + 10 * 60 * 1000; // 10 minutos

    // Guardar usuario pendiente de verificación
    const { data, error } = await supabase.from('users').insert({
      phone, name, pin, plan: plan || 'personal',
      partner_phone, partner_name, business_name,
      status: 'pending', // pendiente hasta verificar
      verify_code: verifyCode, verify_expiry: verifyExpiry
    }).select().single();
    if (error) throw error;

    // Enviar código por WhatsApp
    await sendWhatsApp(phone,
      `👋 ¡Hola ${name || ''}! Bienvenido a *MiCaja*\n\n` +
      `🔢 Tu código de verificación es:\n\n` +
      `*${verifyCode}*\n\n` +
      `⏱ Expira en 10 minutos.\n` +
      `Ingrésalo en la web para activar tu cuenta.`
    );

    const { pin: _, verify_code: __, ...user } = data;
    res.json({ ok: true, user, needsVerification: true });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Error al registrar' });
  }
});

// Verificar código de WhatsApp
app.post('/api/auth/verify', async (req, res) => {
  try {
    const { phone: rawPhone, code } = req.body;
    const phone = normalizePhone(rawPhone);
    const { data: user } = await supabase.from('users').select('*').eq('phone', phone).single();
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    if (user.verify_code !== code) return res.status(401).json({ error: 'Código incorrecto' });
    if (user.verify_expiry < Date.now()) return res.status(401).json({ error: 'Código expirado. Regístrate de nuevo.' });

    // Activar cuenta
    await supabase.from('users').update({ status: 'active', verify_code: null, verify_expiry: null }).eq('id', user.id);

    // Mensaje de bienvenida
    await sendWhatsApp(phone,
      `✅ *¡Cuenta verificada!*\n\n` +
      `Bienvenido a MiCaja ${user.name || ''}.\n\n` +
      `📱 Puedes usarme aquí por WhatsApp o desde:\n` +
      `🌐 milkomercios.in/MiCaja/login.html\n\n` +
      `Escribe *ayuda* para ver todo lo que puedo hacer.`
    );

    const { pin: _, verify_code: __, ...safeUser } = user;
    res.json({ ok: true, user: { ...safeUser, status: 'active' } });
  } catch (err) {
    res.status(500).json({ error: 'Error al verificar' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone: rawPhone, pin } = req.body;
    if (!rawPhone || !pin) return res.status(400).json({ error: 'Teléfono y PIN requeridos' });
    const phone = normalizePhone(rawPhone);
    const { data: user, error } = await supabase.from('users').select('*').eq('phone', phone).eq('pin', pin).single();
    if (error || !user) return res.status(401).json({ error: 'Número o PIN incorrecto' });
    if (user.status === 'pending') return res.status(403).json({ error: 'Cuenta pendiente de verificación. Revisa tu WhatsApp.' });
    const { pin: _, verify_code: __, ...safeUser } = user;
    res.json({ ok: true, user: safeUser });
  } catch (err) { res.status(500).json({ error: 'Error al ingresar' }); }
});

app.post('/api/auth/reset-pin', async (req, res) => {
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
// Obtener movimientos filtrados por módulo
app.get('/api/movements/:userId', async (req, res) => {
  try {
    const { module } = req.query; // ?module=personal o ?module=comerciantes
    let query = supabase.from('movements').select('*').eq('user_id', req.params.userId).order('date', { ascending: false }).limit(200);
    if (module) query = query.eq('module', module);
    const { data, error } = await query;
    if (error) throw error;
    res.json({ ok: true, movements: data });
  } catch (err) { res.status(500).json({ error: 'Error al obtener movimientos' }); }
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

// Agregar miembro a viaje existente
app.post('/api/trips/:id/members', async (req, res) => {
  try {
    const { name, phone } = req.body;
    if (!name) return res.status(400).json({ error: 'Nombre requerido' });
    const { data, error } = await supabase.from('trip_members').insert({ trip_id: req.params.id, name, phone: phone || null }).select().single();
    if (error) throw error;
    res.json({ ok: true, member: data });
  } catch (err) { res.status(500).json({ error: 'Error al agregar miembro' }); }
});

// Actualizar teléfono de miembro
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

// Eliminar miembro del viaje
app.delete('/api/trips/:tripId/members/:memberId', async (req, res) => {
  try {
    await supabase.from('trip_members').delete().eq('id', req.params.memberId);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Error al eliminar miembro' }); }
});

// Editar nombre o estado del viaje
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

// Eliminar viaje
app.delete('/api/trips/:id', async (req, res) => {
  try {
    await supabase.from('trip_expenses').delete().eq('trip_id', req.params.id);
    await supabase.from('trip_members').delete().eq('trip_id', req.params.id);
    await supabase.from('trips').delete().eq('id', req.params.id);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Error al eliminar' }); }
});

// Registrar pago/abono de deuda en viaje
app.post('/api/trips/:id/debt-payments', async (req, res) => {
  try {
    const { debt_key, amount, from_name, to_name } = req.body;
    const { data, error } = await supabase.from('trip_debt_payments').insert({
      trip_id: req.params.id, debt_key, amount, from_name, to_name
    }).select().single();
    if (error) throw error;
    res.json({ ok: true, payment: data });
  } catch (err) { res.status(500).json({ error: 'Error al registrar pago' }); }
});

// Obtener pagos de deudas de un viaje
app.get('/api/trips/:id/debt-payments', async (req, res) => {
  try {
    const { data } = await supabase.from('trip_debt_payments').select('*').eq('trip_id', req.params.id);
    res.json({ ok: true, payments: data || [] });
  } catch (err) { res.status(500).json({ error: 'Error' }); }
});

// Enviar recordatorio de deuda por WhatsApp
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
      `✈️ *${trip_name}*\n` +
      `━━━━━━━━━━━━━━━━\n` +
      `💸 Deuda original: *$${totalOriginal.toLocaleString()} COP*\n` +
      (abonado > 0 ? `✅ Ya abonaste: *$${abonado.toLocaleString()} COP*\n` : ``) +
      `⚠️ Saldo pendiente: *$${pendiente.toLocaleString()} COP*\n` +
      `━━━━━━━━━━━━━━━━\n\n` +
      `*${to_name}* puso ese dinero de su bolsillo por ti durante el viaje. Cuando puedas coordina el pago con él/ella.\n\n` +
      `_Para que *${to_name}* deje de enviarte estos recordatorios automáticos, pídele que marque la deuda como pagada en MiCaja una vez hagas la transferencia._ 😊\n\n` +
      `_MiCaja · milkomercios.in/MiCaja_`;

    await sendWhatsApp(finalPhone, msg);

    if (sender_phone) {
      await sendWhatsApp(sender_phone,
        `✅ Recordatorio enviado a *${from_name}*\n` +
        `💸 Saldo pendiente: *$${pendiente.toLocaleString()} COP*\n` +
        `✈️ Viaje: *${trip_name}*`
      );
    }

    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Error al enviar recordatorio' }); }
});
app.post('/api/trips/:id/finalizar', async (req, res) => {
  try {
    const { user_phone } = req.body;
    const { data: trip } = await supabase.from('trips').select('*, trip_members(*), trip_expenses(*)').eq('id', req.params.id).single();
    if (!trip) return res.status(404).json({ error: 'Viaje no encontrado' });

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

    // Calcular deudas
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

    for (const member of members) {
      if (!member.phone) continue;
      const phone = member.phone.replace(/[\s\-\+\(\)]/g,'').replace(/^0/,'').replace(/^57/,'57');
      const finalPhone = phone.startsWith('57') ? phone : '57' + phone;
      const myBalance = Math.round(balances[member.name] || 0);
      const myDebts = debts.filter(d => d.from === member.name);
      const myCredits = debts.filter(d => d.to === member.name);

      let msg = `✈️ *Viaje: ${trip.name}*\n📅 ${fecha}\n━━━━━━━━━━━━━\n`;
      msg += `Hola *${member.name}*!\n\n`;
      msg += `💰 Gasto total: *$${total.toLocaleString()}*\n`;
      msg += `📊 Tu balance: *${myBalance>=0?'+':''}$${myBalance.toLocaleString()}*\n\n`;
      if (myDebts.length) { msg += `💸 *Debes pagarle a:*\n`; myDebts.forEach(d => { msg += `  • ${d.to}: $${d.amount.toLocaleString()}\n`; }); msg += '\n'; }
      if (myCredits.length) { msg += `💵 *Te deben pagarte:*\n`; myCredits.forEach(d => { msg += `  • ${d.from}: $${d.amount.toLocaleString()}\n`; }); msg += '\n'; }
      if (!myDebts.length && !myCredits.length) msg += `✅ ¡Estás al día!\n\n`;
      msg += `_Enviado desde MiCaja_`;

      await sendWhatsApp(finalPhone, msg);
      phonesSent.push(member.name);
    }

    if (user_phone) {
      await sendWhatsApp(user_phone,
        `🏁 *Viaje "${trip.name}" finalizado*\n💰 Total: *$${total.toLocaleString()}*\n👥 ${members.map(m=>m.name).join(', ')}\n${phonesSent.length?`📱 Resumen enviado a: ${phonesSent.join(', ')}`:'(Sin números registrados)'}`
      );
    }

    await supabase.from('trips').update({ status: 'finished' }).eq('id', req.params.id);
    res.json({ ok: true, sent: phonesSent.length, total });
  } catch (err) {
    console.error('Finalizar error:', err);
    res.status(500).json({ error: 'Error al finalizar viaje' });
  }
});

app.post('/api/trips/:tripId/expenses', async (req, res) => {
  try {
    const { description, amount, category, payer, split_between } = req.body;
    const { data, error } = await supabase.from('trip_expenses').insert({ trip_id: req.params.tripId, description, amount, category: category || 'General', payer, split_between }).select().single();
    if (error) throw error;
    res.json({ ok: true, expense: data });
  } catch (err) { res.status(500).json({ error: 'Error al agregar gasto' }); }
});

app.delete('/api/trips/:tripId/expenses/:expId', async (req, res) => {
  try {
    await supabase.from('trip_expenses').delete().eq('id', req.params.expId);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Error al eliminar gasto' }); }
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

    // Manejar audios, imágenes, stickers, etc.
    if (msg.type === 'audio' || msg.type === 'voice') {
      await sendWhatsApp(from, `🎤 No proceso mensajes de voz todavía.\n\nEscríbeme el gasto o ingreso así:\n💸 _"pagué luz 80mil"_\n💵 _"me ingresaron 200mil"_`);
      return res.sendStatus(200);
    }
    if (msg.type === 'image' || msg.type === 'video' || msg.type === 'document' || msg.type === 'sticker') {
      await sendWhatsApp(from, `📎 Solo proceso mensajes de texto por ahora.\n\nEscríbeme lo que quieres registrar 😊`);
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
// PROCESAR MENSAJES DE WHATSAPP
// ══════════════════════════════════════
async function processWhatsAppMessage(phone, text) {
  let { data: user } = await supabase.from('users').select('*').eq('phone', phone).single();
  const lower = text.toLowerCase().trim();

  // Sesión para flujos multi-paso
  let { data: session } = await supabase.from('wa_sessions').select('*').eq('phone', phone).single();
  const ctx = session?.context ? JSON.parse(session.context) : {};

  async function setCtx(newCtx) {
    const merged = { ...ctx, ...newCtx };
    if (session) { await supabase.from('wa_sessions').update({ context: JSON.stringify(merged), last_message: text, updated_at: new Date() }).eq('id', session.id); }
    else { await supabase.from('wa_sessions').insert({ phone, context: JSON.stringify(merged), last_message: text }); session = { id: 'new' }; }
    return merged;
  }
  async function clearCtx() { if (session) await supabase.from('wa_sessions').update({ context: '{}' }).eq('id', session.id); }

  // ═══ REGISTRO PASO 1: elegir plan ═══
  if (!user && ['registrar','registro','empezar','comenzar'].includes(lower)) {
    await setCtx({ step: 'register_plan' });
    await sendWhatsApp(phone,
      `🎉 ¡Vamos a crear tu cuenta!\n\n¿Para qué quieres usar MiCaja?\n\n` +
      `*1.* 👤 Personal — mis gastos diarios\n` +
      `*2.* 💑 Pareja — finanzas juntos\n` +
      `*3.* ✈️ Viajes — dividir cuentas\n` +
      `*4.* 🏪 Negocio — mi emprendimiento\n\nResponde con el número`
    );
    return;
  }

  // ═══ REGISTRO PASO 2: recibir plan ═══
  if (!user && ctx.step === 'register_plan') {
    const planMap = {'1':'personal','2':'parejas','3':'viajes','4':'comerciantes','personal':'personal','pareja':'parejas','parejas':'parejas','viaje':'viajes','viajes':'viajes','negocio':'comerciantes','comercio':'comerciantes'};
    const plan = planMap[lower];
    if (!plan) { await sendWhatsApp(phone, `Solo responde *1*, *2*, *3* o *4* 😊`); return; }
    await setCtx({ step: 'register_name', plan });
    await sendWhatsApp(phone, `¿Cómo te llamas? ✍️`);
    return;
  }

  // ═══ REGISTRO PASO 3: nombre y crear cuenta ═══
  if (!user && ctx.step === 'register_name') {
    const name = text.trim();
    const plan = ctx.plan || 'personal';
    const pin = String(Math.floor(1000 + Math.random() * 9000));
    const { data: newUser, error } = await supabase.from('users').insert({ phone, name, pin, plan }).select().single();
    if (!error && newUser) {
      await clearCtx();
      const planNames = {personal:'👤 Personal',parejas:'💑 Pareja',viajes:'✈️ Viajes',comerciantes:'🏪 Negocio'};
      await sendWhatsApp(phone,
        `✅ *¡Listo ${name}!*\n\n📋 Plan: ${planNames[plan]}\n🔐 Tu PIN: *${pin}* (guárdalo para la web)\n\n` +
        `Ya puedes escribirme:\n💸 _"pagué arriendo 800mil"_\n💵 _"me pagaron 2 millones"_\n📊 _"cómo voy?"_\n\n¡Empecemos! 🚀`
      );
    } else { await clearCtx(); await sendWhatsApp(phone, `Algo falló. Escribe *registrar* para intentar de nuevo.`); }
    return;
  }

  // Sin cuenta
  if (!user) {
    await sendWhatsApp(phone, `👋 ¡Hey! Soy *MiCaja* ⚡ Tu asistente de finanzas.\n\nEscribe *registrar* y en 30 segundos tienes cuenta.\n\nO entra a la web:\n🌐 milkomercios.in/MiCaja/MiCaja.html`);
    return;
  }

  // ═══ PIN — detección flexible ═══
  const pinConsulta = /^(mi\s+)?pin$|^(cuál|cual)\s+es\s+mi\s+pin|^(olvidé|olvide|recuperar|recordar|ver)\s+(mi\s+)?pin|^pin\?$/i;
  if (pinConsulta.test(lower)) {
    await sendWhatsApp(phone, `🔐 Tu PIN es: *${user.pin}*\n\nPara cambiarlo escribe:\n_"cambiar pin 1234"_ (pon tus 4 dígitos)`);
    return;
  }
  // Cambiar pin — acepta "cambiar pin 1234", "nuevo pin 1234", "pin 1234", "mi pin es 1234"
  const pinCambio = lower.match(/(?:cambiar\s+pin|nuevo\s+pin|pin\s+nuevo|mi\s+pin\s+es)\s*(\d{4})/i) || lower.match(/^pin\s+(\d{4})$/i);
  if (pinCambio) {
    const newPin = pinCambio[1];
    await supabase.from('users').update({ pin: newPin }).eq('id', user.id);
    await sendWhatsApp(phone, `✅ PIN cambiado a *${newPin}* 🔒\n\nGuárdalo, lo necesitas para entrar a la web.`);
    return;
  }

  // ═══ MÓDULO ACTIVO ═══
  if (['mi módulo','mi modulo','qué módulo','que modulo','módulo actual','modulo actual'].includes(lower)) {
    const planNames = {personal:'👤 Personal',parejas:'💑 Pareja',viajes:'✈️ Viajes',comerciantes:'🏪 Negocio'};
    await sendWhatsApp(phone, `📋 Tu módulo activo: *${planNames[user.plan]||user.plan}*\n\nPara cambiar: _"módulo personal"_, _"módulo pareja"_, _"módulo viajes"_, _"módulo negocio"_`);
    return;
  }
  const moduloMatch = lower.match(/^módulo\s+(.+)|^modulo\s+(.+)/i);
  if (moduloMatch) {
    const req = (moduloMatch[1]||moduloMatch[2]).trim();
    const planMap = {'personal':'personal','pareja':'parejas','parejas':'parejas','viaje':'viajes','viajes':'viajes','negocio':'comerciantes','comercio':'comerciantes','comerciante':'comerciantes'};
    const plan = planMap[req];
    if (plan) {
      await supabase.from('users').update({ plan }).eq('id', user.id);
      const planNames = {personal:'👤 Personal',parejas:'💑 Pareja',viajes:'✈️ Viajes',comerciantes:'🏪 Negocio'};
      await sendWhatsApp(phone, `✅ Módulo cambiado a *${planNames[plan]}*\n\nAhora tus registros van a ese módulo 💪`);
    } else {
      await sendWhatsApp(phone, `Módulos: *personal*, *pareja*, *viajes*, *negocio*`);
    }
    return;
  }

  // ═══ NOMBRE ═══
  if (lower.startsWith('mi nombre es ') || lower.startsWith('me llamo ')) {
    const name = text.replace(/^(mi nombre es |me llamo )/i, '').trim();
    if (name) { await supabase.from('users').update({ name }).eq('id', user.id); await sendWhatsApp(phone, `Mucho gusto *${name}* 😊`); }
    return;
  }

  // ═══ PLAN ═══
  if (lower === 'cambiar plan' || lower === 'mi plan') {
    const planNames = {personal:'👤 Personal',parejas:'💑 Pareja',viajes:'✈️ Viajes',comerciantes:'🏪 Negocio'};
    await sendWhatsApp(phone, `Tu plan actual: *${planNames[user.plan]||user.plan}*\n\nPara cambiar escribe:\n_"plan personal"_\n_"plan pareja"_\n_"plan viajes"_\n_"plan negocio"_`);
    return;
  }
  if (lower.startsWith('plan ')) {
    const planMap = {'personal':'personal','pareja':'parejas','parejas':'parejas','viaje':'viajes','viajes':'viajes','negocio':'comerciantes','comercio':'comerciantes'};
    const plan = planMap[lower.replace('plan ','').trim()];
    if (plan) {
      await supabase.from('users').update({ plan }).eq('id', user.id);
      const planNames = {personal:'👤 Personal',parejas:'💑 Pareja',viajes:'✈️ Viajes',comerciantes:'🏪 Negocio'};
      await sendWhatsApp(phone, `✅ Plan cambiado a *${planNames[plan]}* 💪`);
    } else { await sendWhatsApp(phone, `Opciones: *personal*, *pareja*, *viajes*, *negocio*`); }
    return;
  }

  // ═══ SALUDOS ═══
  if (['hola','hi','hey','buenas','buenos días','buenos dias','buenas tardes','buenas noches','qué más','que mas','inicio'].includes(lower)) {
    const hour = new Date(new Date().toLocaleString('en-US',{timeZone:'America/Bogota'})).getHours();
    const saludo = hour < 12 ? 'Buenos días' : hour < 18 ? 'Buenas tardes' : 'Buenas noches';
    const module = user.plan || 'personal';
    const planNames = {personal:'👤 Personal',parejas:'💑 Pareja',viajes:'✈️ Viajes',comerciantes:'🏪 Negocio'};
    const { data: movs } = await supabase.from('movements').select('type, amount').eq('user_id', user.id).eq('module', module);
    const bal = (movs||[]).reduce((s,m) => s + (m.type==='income' ? Number(m.amount) : -Number(m.amount)), 0);
    await sendWhatsApp(phone,
      `${saludo} ${user.name||''}! 👋\n\n` +
      `Módulo: *${planNames[module]}*\n` +
      `${movs&&movs.length ? `Balance: *$${bal.toLocaleString()}*\n` : ''}` +
      `\n¿Qué necesitas?\n💸 _"pagué luz 80mil"_\n💵 _"me ingresaron 200mil"_\n📊 _"cómo voy?"_\n📄 _"informe"_\n🔐 _"pin"_\n❓ _"ayuda"_`
    );
    return;
  }

  // ═══ AYUDA ═══
  if (['ayuda','help','?','comandos','opciones','qué puedo hacer','que puedo hacer','menu','menú'].includes(lower)) {
    const planNames = {personal:'👤 Personal',parejas:'💑 Pareja',viajes:'✈️ Viajes',comerciantes:'🏪 Negocio'};
    await sendWhatsApp(phone,
      `📋 *Comandos MiCaja:*\n\n` +
      `💸 Gasto: _"pagué luz 80mil"_\n` +
      `💵 Ingreso: _"me ingresaron 200mil"_\n` +
      `📊 Resumen: _"cómo voy?"_\n` +
      `📄 Informe: _"informe"_ o _"pdf"_\n` +
      `🗑 Borrar: _"borrar"_\n` +
      `🔐 Ver PIN: _"pin"_\n` +
      `🔄 Cambiar PIN: _"cambiar pin 1234"_\n` +
      `📋 Mi módulo: _"mi módulo"_\n` +
      `🔀 Cambiar módulo: _"módulo negocio"_\n` +
      `✍️ Nombre: _"me llamo Carlos"_\n\n` +
      `Módulo activo: *${planNames[user.plan]||user.plan}*`
    );
    return;
  }

  // ═══ INFORME / PDF ═══
  if (['informe','pdf','reporte','informe pdf','reporte pdf','mi informe','ver informe','informe del mes'].includes(lower)) {
    const module = user.plan || 'personal';
    const planNames = {personal:'Finanzas Personales',parejas:'Finanzas en Pareja',viajes:'Viajes',comerciantes:'Mi Negocio'};
    const { data: movs } = await supabase.from('movements').select('*').eq('user_id', user.id).eq('module', module).order('date',{ascending:false});
    const inc = (movs||[]).filter(m=>m.type==='income').reduce((s,m)=>s+Number(m.amount),0);
    const exp = (movs||[]).filter(m=>m.type==='expense').reduce((s,m)=>s+Number(m.amount),0);
    const bal = inc-exp;
    const byCat = {};
    (movs||[]).filter(m=>m.type==='expense').forEach(m=>{byCat[m.category]=(byCat[m.category]||0)+Number(m.amount);});
    const topCats = Object.entries(byCat).sort((a,b)=>b[1]-a[1]).slice(0,5).map(([c,v])=>`  • ${c}: $${v.toLocaleString()}`).join('\n');
    const last5 = (movs||[]).slice(0,5).map(m=>`  ${m.type==='income'?'💵':'💸'} ${m.description}: $${Number(m.amount).toLocaleString()}`).join('\n');
    const fecha = new Date().toLocaleDateString('es-CO',{day:'2-digit',month:'long',year:'numeric'});
    await sendWhatsApp(phone,
      `📄 *Informe — ${planNames[module]}*\n` +
      `📅 ${fecha} · ${user.name||'Usuario'}\n` +
      `━━━━━━━━━━━━━━━━\n` +
      `💵 Ingresos: *$${inc.toLocaleString()}*\n` +
      `💸 Gastos:   *$${exp.toLocaleString()}*\n` +
      `${bal>=0?'✅':'⚠️'} Balance:  *$${bal.toLocaleString()}*\n` +
      `📋 Total: ${(movs||[]).length} movimientos\n` +
      `${inc>0?`🎯 Ahorro: ${Math.round((bal/inc)*100)}%\n`:'' }` +
      `━━━━━━━━━━━━━━━━\n` +
      `${topCats?`📂 *Top gastos:*\n${topCats}\n━━━━━━━━━━━━━━━━\n`:''}` +
      `🕐 *Últimos movimientos:*\n${last5||'  Sin movimientos'}\n` +
      `━━━━━━━━━━━━━━━━\n` +
      `🌐 Ver completo:\nmilkomercios.in/MiCaja/${module}.html`
    );
    return;
  }

  // ═══ RESUMEN COMPLETO ═══
  if (['resumen','cuánto llevo','cuanto llevo','balance','cómo voy','como voy','cómo voy?','como voy?','estado','saldo'].includes(lower)) {
    const module = user.plan || 'personal';
    const { data: movs } = await supabase.from('movements').select('*').eq('user_id', user.id).eq('module', module);
    const inc = (movs||[]).filter(m => m.type==='income').reduce((s,m) => s+Number(m.amount), 0);
    const exp = (movs||[]).filter(m => m.type==='expense').reduce((s,m) => s+Number(m.amount), 0);
    const bal = inc - exp;
    const count = (movs||[]).length;
    if (count === 0) { await sendWhatsApp(phone, `Aún no tienes movimientos 📭\n\nEscribe _"pagué luz 80mil"_ para empezar.`); return; }

    const byCat = {};
    (movs||[]).filter(m => m.type==='expense').forEach(m => { byCat[m.category] = (byCat[m.category]||0) + Number(m.amount); });
    const topCats = Object.entries(byCat).sort((a,b) => b[1]-a[1]).slice(0,3);
    const catText = topCats.map(([cat,amt]) => `  • ${cat}: $${amt.toLocaleString()}`).join('\n');

    const last3 = (movs||[]).sort((a,b) => new Date(b.created_at)-new Date(a.created_at)).slice(0,3);
    const lastText = last3.map(m => `  ${m.type==='income'?'💵':'💸'} ${m.description}: $${Number(m.amount).toLocaleString()}`).join('\n');

    const tip = bal >= 0 ? (inc > 0 ? `Ahorrando el *${Math.round((bal/inc)*100)}%* de tus ingresos 👏` : '') : `⚠️ Gastos superan ingresos. Revisa ${topCats[0]?topCats[0][0]:'tus gastos'}.`;

    await sendWhatsApp(phone,
      `📊 *Resumen de ${user.name||'tu cuenta'}*\n\n` +
      `💵 Ingresos: *$${inc.toLocaleString()}*\n💸 Gastos: *$${exp.toLocaleString()}*\n${bal>=0?'✅':'⚠️'} Balance: *$${bal.toLocaleString()}*\n📋 ${count} movimientos\n\n` +
      `${topCats.length ? `📂 *Top gastos:*\n${catText}\n\n` : ''}🕐 *Recientes:*\n${lastText}\n\n${tip}`
    );
    return;
  }

  // ═══ DEUDAS ═══
  if (['mis deudas','deudas','qué debo','que debo','cuánto debo','cuanto debo','me deben','qué me deben','que me deben'].includes(lower)) {
    try {
      const { data: debts } = await supabase.from('debts').select('*').eq('user_id', user.id).eq('status', 'pending').or('status.eq.partial');
      const debo = (debts || []).filter(d => d.type === 'debo');
      const meDeben = (debts || []).filter(d => d.type === 'me_deben');
      const totalDebo = debo.reduce((s,d) => s + Number(d.amount) - Number(d.paid || 0), 0);
      const totalMeDeben = meDeben.reduce((s,d) => s + Number(d.amount) - Number(d.paid || 0), 0);

      let msg = `🤝 *Mis Deudas*\n\n`;
      msg += `💸 Yo debo: *$${totalDebo.toLocaleString()}*\n`;
      msg += `💵 Me deben: *$${totalMeDeben.toLocaleString()}*\n`;
      msg += `⚖️ Balance: *${totalMeDeben - totalDebo >= 0 ? '+' : ''}$${(totalMeDeben - totalDebo).toLocaleString()}*\n\n`;

      if (debo.length) {
        msg += `📋 *Lo que debo:*\n`;
        debo.slice(0,5).forEach(d => { msg += `  • ${d.person_name}: $${(Number(d.amount)-Number(d.paid||0)).toLocaleString()}\n`; });
      }
      if (meDeben.length) {
        msg += `\n📋 *Lo que me deben:*\n`;
        meDeben.slice(0,5).forEach(d => { msg += `  • ${d.person_name}: $${(Number(d.amount)-Number(d.paid||0)).toLocaleString()}\n`; });
      }
      msg += `\n🌐 Ver completo: milkomercios.in/MiCaja/deudas.html`;
      await sendWhatsApp(phone, msg);
    } catch(e) {
      await sendWhatsApp(phone, `🤝 Para ver tus deudas entra a:\n🌐 milkomercios.in/MiCaja/deudas.html`);
    }
    return;
  }

  // Registrar deuda por WhatsApp: "le debo 50mil a Juan", "Carlos me debe 80mil"
  const deboMatch = lower.match(/(?:le debo|debo)\s+(\d+[\d.,]*\s*(?:mil|k|m)?)\s+(?:a|le a)?\s*(.+)/i);
  const meDebenMatch = lower.match(/(.+)\s+me debe\s+(\d+[\d.,]*\s*(?:mil|k|m)?)/i);

  if (deboMatch) {
    const amountRaw = deboMatch[1]; const persona = deboMatch[2].trim();
    const amount = parseFloat(amountRaw.replace(/mil|k/i,'').replace(/[.,]/g,'')) * (amountRaw.match(/mil|k/i) ? 1000 : 1);
    await supabase.from('debts').insert({ user_id: user.id, type: 'debo', person_name: persona, amount, status: 'pending', paid: 0 });
    await sendWhatsApp(phone, `💸 Deuda registrada:\nLe debes *$${amount.toLocaleString()}* a *${persona}*\n\nEscribe _"mis deudas"_ para ver el resumen.`);
    return;
  }
  if (meDebenMatch) {
    const persona = meDebenMatch[1].trim(); const amountRaw = meDebenMatch[2];
    const amount = parseFloat(amountRaw.replace(/mil|k/i,'').replace(/[.,]/g,'')) * (amountRaw.match(/mil|k/i) ? 1000 : 1);
    await supabase.from('debts').insert({ user_id: user.id, type: 'me_deben', person_name: persona, amount, status: 'pending', paid: 0 });
    await sendWhatsApp(phone, `💵 Deuda registrada:\n*${persona}* te debe *$${amount.toLocaleString()}*\n\nEscribe _"mis deudas"_ para ver el resumen.`);
    return;
  }
  const webCmds = ['web','link','página','pagina','entrar web','abrir web','ver web','ir a la web','iniciar sesion web','iniciar sesión web','ir al portal','portal','dashboard','ir al dashboard','abrir dashboard','usar web','abrir app','ir a la app','la app','la web','entrar','entrar al sistema','sistema','plataforma','ver mis datos','ver datos','datos web','mis datos web','ingresar','ingresar a la web','acceder','acceso web','login','entrar a micaja','abrir micaja','micaja web','ver micaja','mi cuenta web','mi cuenta','ver cuenta'];
  if (webCmds.includes(lower) || webCmds.some(c => lower.includes(c))) {
    await sendWhatsApp(phone,
      `🌐 *Accede a MiCaja desde la web:*\n\n` +
      `👉 milkomercios.in/MiCaja/login.html\n\n` +
      `📱 Tu número: *${phone}*\n` +
      `🔐 Tu PIN: *${user.pin}*\n\n` +
      `_Ingresa con tu número y PIN para ver tus datos, gráficos e informes completos._`
    );
    return;
  }

  // ═══ PAGAR / SUSCRIPCIÓN ═══
  if (['pagar','suscripción','suscripcion','pago','mi suscripción','activar','renovar','pagar micaja'].includes(lower)) {
    try {
      // Generar link directo de pago con token
      const linkRes = await axios.get(`https://micaja-backend-production.up.railway.app/api/payments/link/${phone}`);
      if (linkRes.data.ok) {
        await sendWhatsApp(phone,
          `💳 *Suscripción MiCaja*\n\n` +
          `📋 Acceso completo a todos los módulos\n` +
          `💰 *$20.000 COP / mes*\n` +
          `💳 Tarjeta, PSE, Nequi\n\n` +
          `👇 Haz clic para pagar directo (sin login):\n${linkRes.data.url}\n\n` +
          `⏱ _El link expira en 30 minutos_`
        );
      }
    } catch(e) {
      await sendWhatsApp(phone,
        `💳 Para pagar tu suscripción entra a:\n🌐 milkomercios.in/MiCaja/dashboard.html`
      );
    }
    return;
  }
  if (['borrar último','borrar ultimo','borrar','eliminar último','eliminar ultimo','deshacer'].includes(lower)) {
    const module = user.plan || 'personal';
    const { data: last } = await supabase.from('movements').select('id, description, amount, type, category').eq('user_id', user.id).eq('module', module).order('created_at',{ascending:false}).limit(1).single();
    if (last) {
      await supabase.from('movements').delete().eq('id', last.id);
      await sendWhatsApp(phone, `🗑 Borré el último movimiento:\n${last.type==='income'?'💵':'💸'} *${last.description}* — $${Number(last.amount).toLocaleString()}\n📂 ${last.category}`);
    } else {
      await sendWhatsApp(phone, `No tienes movimientos para borrar 📭`);
    }
    return;
  }

  // ═══ VER ÚLTIMOS MOVIMIENTOS ═══
  if (['últimos','ultimos','últimos movimientos','ver últimos','mis movimientos','ver movimientos'].includes(lower)) {
    const module = user.plan || 'personal';
    const { data: movs } = await supabase.from('movements').select('*').eq('user_id', user.id).eq('module', module).order('created_at',{ascending:false}).limit(5);
    if (!movs || !movs.length) { await sendWhatsApp(phone, `No tienes movimientos aún 📭`); return; }
    const lista = movs.map((m,i) => `${i+1}. ${m.type==='income'?'💵':'💸'} ${m.description} — $${Number(m.amount).toLocaleString()}\n   📂 ${m.category} · ${m.date}`).join('\n\n');
    await sendWhatsApp(phone, `🕐 *Últimos 5 movimientos:*\n\n${lista}\n\nPara borrar el último escribe _"borrar"_`);
    return;
  }

  // ═══ CONFIRMAR CATEGORÍA (flujo de 2 pasos) ═══
  if (ctx.step === 'confirm_cat') {
    const cats = {'1':'Alimentación','2':'Arriendo','3':'Servicios','4':'Transporte','5':'Salud','6':'Entretenimiento','7':'Educación','8':'Proveedores','9':'Nómina','10':'Ventas','11':'Salario','0':'Otros'};
    const finalCat = cats[lower] || (Object.values(cats).map(c=>c.toLowerCase()).includes(lower) ? lower.charAt(0).toUpperCase()+lower.slice(1) : null);

    if (lower === 'cancelar' || lower === 'no') {
      await clearCtx();
      await sendWhatsApp(phone, `❌ Cancelado. No se guardó nada.`);
      return;
    }

    const useCat = finalCat || (lower === 'si' || lower === 'sí' || lower === 'ok' || lower === 'listo' ? ctx.category : null);
    if (useCat) {
      const module = user.plan || 'personal';
      const planNames = {personal:'👤',parejas:'💑',viajes:'✈️',comerciantes:'🏪'};
      const { error } = await supabase.from('movements').insert({user_id: user.id, type: ctx.type, amount: ctx.amount, description: ctx.description, category: useCat, source: 'whatsapp', module}).select().single();
      if (!error) {
        await clearCtx();
        const { data: movs } = await supabase.from('movements').select('type, amount').eq('user_id', user.id).eq('module', module);
        const bal = (movs||[]).reduce((s,m) => s + (m.type==='income' ? Number(m.amount) : -Number(m.amount)), 0);
        if (ctx.type === 'income') {
          await sendWhatsApp(phone, `✅ *Ingreso guardado*\n\n💵 ${ctx.description}\n💰 +$${Number(ctx.amount).toLocaleString()}\n📂 ${useCat}\n${planNames[module]} ${module}\n\nBalance: *$${bal.toLocaleString()}* 📊`);
        } else {
          await sendWhatsApp(phone, `✅ *Gasto guardado*\n\n💸 ${ctx.description}\n💰 -$${Number(ctx.amount).toLocaleString()}\n📂 ${useCat}\n${planNames[module]} ${module}\n\nTe queda: *$${bal.toLocaleString()}* ${bal<0?'⚠️':'👍'}`);
        }
      }
    } else {
      await sendWhatsApp(phone, `Elige una categoría:\n\n*1* Alimentación · *2* Arriendo · *3* Servicios\n*4* Transporte · *5* Salud · *6* Entretenimiento\n*7* Educación · *8* Proveedores · *9* Nómina\n*10* Ventas · *11* Salario · *0* Otros\n\nO escribe el nombre · _"cancelar"_ para anular`);
    }
    return;
  }

  // ═══ GASTO O INGRESO — parser con confirmación de categoría ═══
  const parsed = await parseWithAI(lower, user.name, user.plan);
  if (parsed) {
    const module = user.plan || 'personal';
    const planNames = {personal:'👤 Personal',parejas:'💑 Pareja',viajes:'✈️ Viajes',comerciantes:'🏪 Negocio'};
    const emoji = parsed.type === 'income' ? '💵' : '💸';
    const label = parsed.type === 'income' ? 'ingreso' : 'gasto';
    await setCtx({step: 'confirm_cat', type: parsed.type, amount: parsed.amount, description: parsed.description, category: parsed.category});
    await sendWhatsApp(phone,
      `${emoji} Entendí un *${label}*:\n\n` +
      `📝 *${parsed.description}*\n` +
      `💰 $${parsed.amount.toLocaleString()}\n` +
      `📂 Categoría sugerida: *${parsed.category}*\n` +
      `📋 Módulo: *${planNames[module]}*\n\n` +
      `¿Correcto? Escribe *sí* para guardar\n` +
      `O elige otra categoría:\n` +
      `*1* Alimentación · *2* Arriendo · *3* Servicios\n` +
      `*4* Transporte · *5* Salud · *6* Entretenimiento\n` +
      `*7* Educación · *8* Proveedores · *9* Nómina\n` +
      `*10* Ventas · *11* Salario · *0* Otros\n` +
      `❌ _"cancelar"_ para anular`
    );
    return;
  }

  // ═══ NO ENTENDIÓ ═══
  await sendWhatsApp(phone, `Mmm, no pillé eso 🤔\n\nPrueba así:\n💸 _"pagué luz 80mil"_\n💵 _"me ingresaron 200mil"_\n📊 _"cómo voy?"_\n📄 _"informe"_\n\nO escribe *ayuda* para ver todo.`);
}

// ══════ BUSCAR USUARIO POR TELÉFONO (para debug y sync) ══════
app.get('/api/user/phone/:phone', async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('id, name, phone, plan, role, status, created_at').eq('phone', req.params.phone).single();
    if (!user) return res.status(404).json({ error: 'No encontrado' });
    res.json({ ok: true, user });
  } catch (err) { res.status(500).json({ error: 'Error' }); }
});

// ══════ PARSER FINANCIERO CON IA (Claude API) ══════
async function parseWithAI(text, userName, plan) {
  try {
    const ANTHROPIC_KEY = process.env.ANTHROPIC_KEY;
    if (!ANTHROPIC_KEY) return parseFinancialMessage(text); // fallback si no hay key

    const res = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 300,
      messages: [{
        role: 'user',
        content: `Eres el asistente financiero de MiCaja para Colombia. El usuario se llama ${userName||'usuario'} y usa el módulo ${plan||'personal'}.

Analiza este mensaje y extrae la información financiera. Responde SOLO con JSON sin markdown:
{"type":"income"|"expense"|"unknown","amount":number_in_COP,"description":"descripcion_limpia","category":"categoria"}

Categorías válidas para gastos: Alimentación, Arriendo, Servicios, Transporte, Salud, Entretenimiento, Educación, Nómina, Proveedores, Mercancía, Otros
Categorías para ingresos: Ventas, Salario, Freelance, Cobros, Otros ingresos

Reglas:
- "mil" = 1000, "millón/millones" = 1000000, "k" = 1000
- Si no hay monto claro, type = "unknown"
- Descripción debe ser corta y limpia (2-4 palabras max)
- Detecta contexto colombiano: "fiao/fiado" = gasto, "abono" = ingreso, "cuota" = gasto

Mensaje: "${text}"`
      }]
    }, {
      headers: { 'x-api-key': ANTHROPIC_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' }
    });

    const raw = res.data.content[0].text.trim();
    const parsed = JSON.parse(raw);
    if (parsed.type === 'unknown' || !parsed.amount) return null;
    return parsed;
  } catch (e) {
    console.error('AI parse error:', e.message);
    return parseFinancialMessage(text); // fallback al parser simple
  }
}

// ══════ PARSER FINANCIERO SIMPLE (fallback) ══════
function parseFinancialMessage(text) {
  let n = text
    .replace(/(\d+)\s*mil/gi, (_,x) => String(Number(x)*1000))
    .replace(/(\d+\.?\d*)\s*m(?:illones?)?/gi, (_,x) => String(Number(x)*1000000))
    .replace(/(\d+)k/gi, (_,x) => String(Number(x)*1000));

  const amtMatch = n.match(/\$?\s*([\d,.]+)/);
  if (!amtMatch) return null;
  const amount = parseFloat(amtMatch[1].replace(/[,.]/g, ''));
  if (!amount || amount <= 0) return null;

  // Palabras de INGRESO — mucho más amplio
  const incWords = [
    'vendí','vendi','cobré','cobre','ingreso','me pagaron','recibí','recibi',
    'venta','gané','gane','salario','sueldo','ingresaron','me ingresaron',
    'entró','entro','llegó','llego','depositaron','me depositaron',
    'abonaron','me abonaron','pagaron','recaudo','recaudé','recaude',
    'facturé','facture','cobré','cobre','honorarios','comisión','comision',
    'transferencia','transfer','me cayó','me cayo','cayó','cayeron'
  ];

  // Palabras de GASTO — para confirmar gasto
  const expWords = [
    'pagué','pague','gasté','gaste','compré','compre','cobró','cobro',
    'salió','salio','pagamos','compramos','gastamos','invertí','invert'
  ];

  let type = 'expense'; // default
  const textLower = n.toLowerCase();
  for (const w of incWords) { if (textLower.includes(w)) { type = 'income'; break; } }
  // Si detectó income pero también tiene palabra de gasto explícita, verificar contexto
  if (type === 'expense') {
    for (const w of expWords) { if (textLower.includes(w)) { type = 'expense'; break; } }
  }

  // Limpiar descripción
  let desc = n
    .replace(/\$?\s*[\d,.]+/g, '')
    .replace(/pagué|pague|gasté|gaste|compré|compre|vendí|vendi|cobré|cobre|ingreso|me pagaron|recibí|recibi|gané|gane|ingresaron|me ingresaron|entró|entro|llegó|llego|depositaron|me depositaron/gi, '')
    .replace(/^\s*(de|en|por|el|la|un|una|los|las|del|al)\s+/i, '')
    .replace(/\s+/g, ' ')
    .trim();

  if (!desc || desc.length < 2) desc = type === 'income' ? 'Ingreso' : 'Gasto';
  desc = desc.charAt(0).toUpperCase() + desc.slice(1);
  return { type, amount, description: desc, category: autoCategory(desc, type) };
}

// ══════ AUTO-CATEGORIZACIÓN ══════
function autoCategory(desc, type) {
  if (type === 'income') {
    if (/venta|vendí|vendi/i.test(desc)) return 'Ventas';
    if (/salario|sueldo|nómina|nomina/i.test(desc)) return 'Salario';
    if (/cobr/i.test(desc)) return 'Cobros';
    return 'Otros ingresos';
  }
  const d = desc.toLowerCase();
  if (/luz|agua|gas|internet|teléfono|telefono|servicio/i.test(d)) return 'Servicios';
  if (/arriendo|alquiler|renta/i.test(d)) return 'Arriendo';
  if (/mercado|supermercado|comida|almuerzo|desayuno|cena|restaurante/i.test(d)) return 'Alimentación';
  if (/uber|taxi|bus|transporte|gasolina|parqueo/i.test(d)) return 'Transporte';
  if (/salud|médico|medico|farmacia|droguería|medicina/i.test(d)) return 'Salud';
  if (/netflix|spotify|cine|entretenimiento|suscripción/i.test(d)) return 'Entretenimiento';
  if (/nómina|nomina|empleado|sueldo/i.test(d)) return 'Nómina';
  if (/proveedor|mercancía|inventario|insumo/i.test(d)) return 'Proveedores';
  if (/colegio|universidad|educación|curso/i.test(d)) return 'Educación';
  return 'Otros';
}

// ══════ ENVIAR WHATSAPP ══════
async function sendWhatsApp(to, message) {
  if (!WA_TOKEN || !WA_PHONE_ID) { console.log(`[WA SIM] → ${to}: ${message}`); return; }
  try {
    const phone = to.replace(/[+\s-]/g, '');
    await axios.post(`https://graph.facebook.com/v18.0/${WA_PHONE_ID}/messages`, { messaging_product: 'whatsapp', to: phone, type: 'text', text: { body: message } }, { headers: { 'Authorization': `Bearer ${WA_TOKEN}`, 'Content-Type': 'application/json' } });
    console.log(`✅ WA → ${phone}`);
  } catch (err) { console.error('WA Error:', err.response?.data || err.message); }
}

// ══════════════════════════════════════
// ADMIN — Middleware de verificación
// ══════════════════════════════════════
async function verifyAdmin(req, res, next) {
  const phone = req.headers['x-admin-phone'];
  if (!phone) return res.status(401).json({ error: 'No autorizado' });
  const { data: user } = await supabase.from('users').select('role').eq('phone', phone).single();
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'Solo administradores' });
  next();
}

// Listar todos los usuarios con conteo de movimientos e ingresos
app.get('/api/admin/users', verifyAdmin, async (req, res) => {
  try {
    const { data: users } = await supabase.from('users').select('*').order('created_at', { ascending: false });
    if (!users) return res.json({ ok: true, users: [] });

    const enriched = await Promise.all(users.map(async u => {
      const { data: movs } = await supabase.from('movements').select('type, amount').eq('user_id', u.id);
      const count = (movs || []).length;
      const income = (movs || []).filter(m => m.type === 'income').reduce((s, m) => s + Number(m.amount), 0);
      const { pin: _, verify_code: __, ...safeUser } = u;
      return { ...safeUser, movement_count: count, income_total: income };
    }));

    res.json({ ok: true, users: enriched });
  } catch (err) { res.status(500).json({ error: 'Error al obtener usuarios' }); }
});

// Listar pagos para admin
app.get('/api/admin/payments', verifyAdmin, async (req, res) => {
  try {
    const { data: payments } = await supabase
      .from('payments')
      .select('*, users(name, phone)')
      .order('created_at', { ascending: false })
      .limit(100);
    res.json({ ok: true, payments: payments || [] });
  } catch (err) { res.status(500).json({ error: 'Error al obtener pagos' }); }
});

// Editar usuario (PIN, rol, estado, plan, nombre)
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

// Ver datos completos de un usuario (para admin)
app.get('/api/admin/users/:id/data', verifyAdmin, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users').select('*').eq('id', req.params.id).single();
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

    const { data: movs } = await supabase.from('movements').select('*').eq('user_id', req.params.id).order('created_at', { ascending: false });
    const { data: trips } = await supabase.from('trips').select('*, trip_expenses(*)').eq('user_id', req.params.id);

    const income = (movs || []).filter(m => m.type === 'income').reduce((s, m) => s + Number(m.amount), 0);
    const expense = (movs || []).filter(m => m.type === 'expense').reduce((s, m) => s + Number(m.amount), 0);

    const { pin: _, ...safeUser } = user;
    res.json({
      ok: true,
      user: safeUser,
      summary: { income, expense, balance: income - expense, count: (movs || []).length },
      movements: movs || [],
      trips: trips || []
    });
  } catch (err) { res.status(500).json({ error: 'Error al obtener datos' }); }
});

// Obtener configuración del usuario (ingresos de pareja, etc.)
app.get('/api/users/:id/config', async (req, res) => {
  try {
    const { data } = await supabase.from('user_config').select('*').eq('user_id', req.params.id).single();
    res.json({ ok: true, config: data || null });
  } catch (err) { res.json({ ok: true, config: null }); }
});

// Guardar configuración del usuario
app.post('/api/users/:id/config', async (req, res) => {
  try {
    const { partner_name, partner_income_a, partner_income_b } = req.body;
    const { data, error } = await supabase.from('user_config').upsert({
      user_id: req.params.id, partner_name, partner_income_a, partner_income_b,
      updated_at: new Date()
    }, { onConflict: 'user_id' }).select().single();
    if (error) throw error;
    res.json({ ok: true, config: data });
  } catch (err) { res.status(500).json({ error: 'Error al guardar configuración' }); }
});

// Actualizar datos del usuario (nombre negocio, nombre, etc.)
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

// ══════════════════════════════════════
// DEUDAS — Qué debo / Qué me deben
// ══════════════════════════════════════
app.get('/api/debts/:userId', async (req, res) => {
  try {
    const { data, error } = await supabase.from('debts').select('*').eq('user_id', req.params.userId).order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ ok: true, debts: data || [] });
  } catch (err) { res.status(500).json({ error: 'Error al obtener deudas' }); }
});

app.post('/api/debts', async (req, res) => {
  try {
    const { user_id, type, person_name, amount, description, due_date, note } = req.body;
    if (!user_id || !type || !person_name || !amount) return res.status(400).json({ error: 'Campos requeridos' });
    const { data, error } = await supabase.from('debts').insert({ user_id, type, person_name, amount, description, due_date: due_date || null, note, status: 'pending', paid: 0 }).select().single();
    if (error) throw error;
    res.json({ ok: true, debt: data });
  } catch (err) { res.status(500).json({ error: 'Error al crear deuda' }); }
});

app.post('/api/debts/:id/abono', async (req, res) => {
  try {
    const { amount } = req.body;
    const { data: debt } = await supabase.from('debts').select('amount, paid').eq('id', req.params.id).single();
    if (!debt) return res.status(404).json({ error: 'No encontrada' });
    const newPaid = Number(debt.paid || 0) + Number(amount);
    const newStatus = newPaid >= Number(debt.amount) ? 'paid' : 'partial';
    const { data, error } = await supabase.from('debts').update({ paid: newPaid, status: newStatus }).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json({ ok: true, debt: data });
  } catch (err) { res.status(500).json({ error: 'Error al registrar abono' }); }
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
const crypto = require('crypto');

// Generar link de pago directo por teléfono (para WhatsApp)
app.get('/api/payments/link/:phone', async (req, res) => {
  try {
    const phone = req.params.phone;
    const { data: user } = await supabase.from('users').select('*').eq('phone', phone).single();
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

    const orderId = `MICAJA-${user.id.slice(0,8)}-${Date.now()}`;
    const amount = '20000';
    const currency = 'COP';
    const integString = `${orderId}${amount}${currency}${BOLD_SECRET_KEY}`;
    const integritySignature = crypto.createHash('sha256').update(integString).digest('hex');

    // Token temporal (expira en 30 min)
    const token = crypto.createHash('sha256').update(`${phone}-${Date.now()}-${BOLD_SECRET_KEY}`).digest('hex').slice(0, 16);
    const tokenExpiry = Date.now() + 30*60*1000;

    // Guardar pago pendiente CON el token
    await supabase.from('payments').insert({
      user_id: user.id, amount: 20000, method: 'bold',
      reference: orderId, status: 'pending',
      pay_token: token, token_expiry: tokenExpiry,
      period_start: new Date().toISOString().split('T')[0],
      period_end: new Date(Date.now() + 30*24*60*60*1000).toISOString().split('T')[0]
    });

    const payUrl = `https://milkomercios.in/MiCaja/pagar.html?tel=${phone}&token=${token}`;
    res.json({ ok: true, url: payUrl });
  } catch (err) {
    console.error('Payment link error:', err);
    res.status(500).json({ error: 'Error generando link' });
  }
});

// Obtener datos de pago por token (pagar.html lo llama)
app.get('/api/payments/token/:phone/:token', async (req, res) => {
  try {
    const { phone, token } = req.params;

    // Buscar en tabla payments por teléfono + token
    const { data: user } = await supabase.from('users').select('id').eq('phone', phone).single();
    if (!user) return res.status(404).json({ error: 'Token no encontrado' });

    const { data: payment } = await supabase
      .from('payments')
      .select('*')
      .eq('user_id', user.id)
      .eq('pay_token', token)
      .eq('status', 'pending')
      .order('created_at', { ascending: false })
      .limit(1)
      .single();

    if (!payment) return res.status(404).json({ error: 'Token no encontrado' });
    if (payment.token_expiry < Date.now()) return res.status(401).json({ error: 'Token expirado' });

    // Recalcular integritySignature con el monto correcto en pesos
    const integString = `${payment.reference}20000COP${BOLD_SECRET_KEY}`;
    const integritySignature = crypto.createHash('sha256').update(integString).digest('hex');

    res.json({
      ok: true,
      orderId: payment.reference,
      amount: '20000',
      currency: 'COP',
      integritySignature,
      apiKey: BOLD_API_KEY,
      redirectionUrl: 'https://milkomercios.in/MiCaja/pagar.html',
      description: 'MiCaja - Suscripción mensual $20.000'
    });
  } catch (err) {
    console.error('Token lookup error:', err);
    res.status(500).json({ error: 'Error verificando token' });
  }
});

// Generar parámetros de pago Bold (el checkout se abre desde el frontend web)
app.post('/api/payments/create', async (req, res) => {
  try {
    const { user_id, plan_type = 'mensual' } = req.body;
    if (!user_id) return res.status(400).json({ error: 'user_id requerido' });

    const { data: user } = await supabase.from('users').select('name, phone').eq('id', user_id).single();
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

    // Configurar según plan
    const plans = {
      mensual:  { amount: '20000',  label: 'Suscripción mensual $20.000',   days: 30 },
      anual:    { amount: '200000', label: 'Suscripción anual $200.000',    days: 365 },
      lifetime: { amount: '320000', label: 'Acceso de por vida $320.000',   days: 36500 }
    };
    const plan = plans[plan_type] || plans.mensual;

    const orderId = `MICAJA-${user_id.slice(0,8)}-${Date.now()}`;
    const currency = 'COP';
    const integString = `${orderId}${plan.amount}${currency}${BOLD_SECRET_KEY}`;
    const integritySignature = crypto.createHash('sha256').update(integString).digest('hex');

    await supabase.from('payments').insert({
      user_id, amount: parseInt(plan.amount), method: 'bold',
      reference: orderId, status: 'pending', plan_type,
      period_start: new Date().toISOString().split('T')[0],
      period_end: new Date(Date.now() + plan.days*24*60*60*1000).toISOString().split('T')[0]
    });

    res.json({
      ok: true, orderId, amount: plan.amount, currency,
      integritySignature, apiKey: BOLD_API_KEY,
      redirectionUrl: 'https://milkomercios.in/MiCaja/dashboard.html',
      description: plan.label
    });
  } catch (err) {
    console.error('Bold create error:', err);
    res.status(500).json({ error: 'Error al crear pago' });
  }
});

// Webhook de confirmación de pago Bold
app.post('/api/payments/bold-webhook', async (req, res) => {
  try {
    const event = req.body;
    console.log('💳 Bold webhook:', JSON.stringify(event));

    // Verificar que el pago fue aprobado
    if (event.type !== 'TRANSACTION' || event.data?.transaction?.status !== 'APPROVED') {
      return res.sendStatus(200);
    }

    const orderId = event.data?.transaction?.order_id || event.data?.transaction?.orderId;
    if (!orderId) return res.sendStatus(200);

    // Extraer user_id del orderId (formato: MICAJA-{userId8chars}-{timestamp})
    const parts = orderId.split('-');
    if (parts.length < 2) return res.sendStatus(200);
    const userIdPrefix = parts[1];

    // Buscar el pago pendiente
    const { data: payment } = await supabase
      .from('payments')
      .select('*, users(*)')
      .ilike('reference', `MICAJA-${userIdPrefix}%`)
      .eq('status', 'pending')
      .order('created_at', { ascending: false })
      .limit(1)
      .single();

    if (!payment) return res.sendStatus(200);

    // Actualizar pago a pagado
    await supabase.from('payments').update({ status: 'paid' }).eq('id', payment.id);

    // Activar usuario si estaba inactivo
    await supabase.from('users').update({ status: 'active' }).eq('id', payment.user_id);

    // Notificar por WhatsApp
    const userPhone = payment.users?.phone;
    if (userPhone && WA_TOKEN) {
      await sendWhatsApp(userPhone,
        `✅ *¡Pago recibido!*\n\n` +
        `💰 $20.000 COP — MiCaja mensual\n` +
        `📅 Válido hasta: ${payment.period_end}\n` +
        `🔢 Ref: ${orderId}\n\n` +
        `¡Gracias! Tu acceso está activo 🚀\n` +
        `Sigue usando MiCaja por WhatsApp o en:\n` +
        `🌐 milkomercios.in/MiCaja/dashboard.html`
      );
    }

    res.sendStatus(200);
  } catch (err) {
    console.error('Bold webhook error:', err);
    res.sendStatus(200);
  }
});

// Consultar estado de suscripción
app.get('/api/payments/status/:userId', async (req, res) => {
  try {
    const { data: payment } = await supabase
      .from('payments')
      .select('*')
      .eq('user_id', req.params.userId)
      .eq('status', 'paid')
      .order('created_at', { ascending: false })
      .limit(1)
      .single();

    if (!payment) return res.json({ ok: true, active: false });

    const expired = payment.period_end < new Date().toISOString().split('T')[0];
    res.json({ ok: true, active: !expired, payment });
  } catch (err) {
    res.json({ ok: true, active: false });
  }
});

// ══════ INICIAR ══════
app.listen(PORT, () => {
  console.log(`⚡ MiCaja Backend v2 en puerto ${PORT}`);
  console.log(`📊 Supabase: ${SUPABASE_URL ? '✅' : '⚠️'}`);
  console.log(`📱 WhatsApp: ${WA_TOKEN ? '✅' : '⚠️ simulado'}`);
  console.log(`💳 Bold: ${BOLD_API_KEY ? '✅' : '⚠️ sin configurar'}`);
});
