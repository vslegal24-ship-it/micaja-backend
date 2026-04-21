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

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// ══════ HEALTH CHECK ══════
app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'MiCaja Backend', version: '2.0.0', timestamp: new Date().toISOString() });
});

// ══════ AUTH ══════
app.post('/api/auth/register', async (req, res) => {
  try {
    const { phone, name, pin, plan, partner_phone, partner_name, business_name } = req.body;
    if (!phone || !pin || pin.length !== 4) return res.status(400).json({ error: 'Teléfono y PIN de 4 dígitos requeridos' });
    const { data: existing } = await supabase.from('users').select('id').eq('phone', phone).single();
    if (existing) return res.status(409).json({ error: 'Este número ya tiene cuenta' });
    const { data, error } = await supabase.from('users').insert({ phone, name, pin, plan: plan || 'personal', partner_phone, partner_name, business_name }).select().single();
    if (error) throw error;
    const { pin: _, ...user } = data;
    res.json({ ok: true, user });
  } catch (err) { res.status(500).json({ error: 'Error al registrar' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, pin } = req.body;
    if (!phone || !pin) return res.status(400).json({ error: 'Teléfono y PIN requeridos' });
    const { data: user, error } = await supabase.from('users').select('*').eq('phone', phone).eq('pin', pin).single();
    if (error || !user) return res.status(401).json({ error: 'Número o PIN incorrecto' });
    const { pin: _, ...safeUser } = user;
    res.json({ ok: true, user: safeUser });
  } catch (err) { res.status(500).json({ error: 'Error al ingresar' }); }
});

app.post('/api/auth/reset-pin', async (req, res) => {
  try {
    const { phone } = req.body;
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
    const { data, error } = await supabase.from('movements').select('*').eq('user_id', req.params.userId).order('date', { ascending: false }).limit(100);
    if (error) throw error;
    res.json({ ok: true, movements: data });
  } catch (err) { res.status(500).json({ error: 'Error al obtener movimientos' }); }
});

app.post('/api/movements', async (req, res) => {
  try {
    const { user_id, type, amount, description, category, who, shared, note, date, source } = req.body;
    if (!user_id || !type || !amount || !description) return res.status(400).json({ error: 'Campos requeridos: user_id, type, amount, description' });
    const finalCategory = category || autoCategory(description, type);
    const { data, error } = await supabase.from('movements').insert({ user_id, type, amount, description, category: finalCategory, who, shared, note, date: date || new Date().toISOString().split('T')[0], source: source || 'web' }).select().single();
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
    const { data: movs } = await supabase.from('movements').select('*').eq('user_id', req.params.userId);
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
    const { data: trip, error } = await supabase.from('trips').insert({ user_id, name }).select().single();
    if (error) throw error;
    if (members && members.length > 0) await supabase.from('trip_members').insert(members.map(m => ({ trip_id: trip.id, name: m })));
    res.json({ ok: true, trip });
  } catch (err) { res.status(500).json({ error: 'Error al crear viaje' }); }
});

app.get('/api/trips/:userId', async (req, res) => {
  try {
    const { data } = await supabase.from('trips').select('*, trip_members(*), trip_expenses(*)').eq('user_id', req.params.userId).order('created_at', { ascending: false });
    res.json({ ok: true, trips: data || [] });
  } catch (err) { res.status(500).json({ error: 'Error al obtener viajes' }); }
});

app.post('/api/trips/:tripId/expenses', async (req, res) => {
  try {
    const { description, amount, category, payer, split_between } = req.body;
    const { data, error } = await supabase.from('trip_expenses').insert({ trip_id: req.params.tripId, description, amount, category: category || 'General', payer, split_between }).select().single();
    if (error) throw error;
    res.json({ ok: true, expense: data });
  } catch (err) { res.status(500).json({ error: 'Error al agregar gasto' }); }
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

  // ═══ PIN ═══
  if (['pin','mi pin','olvidé mi pin','olvide mi pin','recordar pin','recuperar pin','cual es mi pin','cuál es mi pin'].includes(lower)) {
    await sendWhatsApp(phone, `🔐 Tu PIN es: *${user.pin}*\n\nPara cambiarlo escribe: _"cambiar pin 1234"_`);
    return;
  }
  if (lower.startsWith('cambiar pin ')) {
    const newPin = lower.replace('cambiar pin ','').trim();
    if (newPin.length === 4 && /^\d{4}$/.test(newPin)) {
      await supabase.from('users').update({ pin: newPin }).eq('id', user.id);
      await sendWhatsApp(phone, `✅ PIN cambiado a *${newPin}* 🔒`);
    } else { await sendWhatsApp(phone, `El PIN debe ser 4 números. Ej: _"cambiar pin 5678"_`); }
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
    const { data: movs } = await supabase.from('movements').select('type, amount').eq('user_id', user.id);
    const bal = (movs||[]).reduce((s,m) => s + (m.type==='income' ? Number(m.amount) : -Number(m.amount)), 0);
    await sendWhatsApp(phone,
      `${saludo} ${user.name||''}! 👋\n\n` +
      `${movs&&movs.length ? `Tu balance: *$${bal.toLocaleString()}*\n\n` : ''}` +
      `¿Qué necesitas?\n💸 _"pagué luz 80mil"_\n💵 _"vendí 350mil"_\n📊 _"cómo voy?"_\n🔐 _"pin"_\n❓ _"ayuda"_`
    );
    return;
  }

  // ═══ AYUDA ═══
  if (['ayuda','help','?','comandos','opciones','qué puedo hacer','que puedo hacer','menu','menú'].includes(lower)) {
    await sendWhatsApp(phone,
      `📋 *Lo que puedo hacer:*\n\n` +
      `💸 Gasto: _"pagué luz 80mil"_\n💵 Ingreso: _"vendí 350mil"_\n📊 Resumen: _"cómo voy?"_\n` +
      `🗑 Borrar: _"borrar último"_\n🔐 PIN: _"pin"_ o _"cambiar pin 1234"_\n` +
      `📋 Plan: _"mi plan"_ o _"plan pareja"_\n✍️ Nombre: _"me llamo Carlos"_`
    );
    return;
  }

  // ═══ RESUMEN COMPLETO ═══
  if (['resumen','cuánto llevo','cuanto llevo','balance','cómo voy','como voy','cómo voy?','como voy?','estado','saldo'].includes(lower)) {
    const { data: movs } = await supabase.from('movements').select('*').eq('user_id', user.id);
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

  // ═══ BORRAR ═══
  if (['borrar último','borrar ultimo','borrar','eliminar último','eliminar ultimo','deshacer'].includes(lower)) {
    const { data: last } = await supabase.from('movements').select('id, description, amount').eq('user_id', user.id).order('created_at',{ascending:false}).limit(1).single();
    if (last) { await supabase.from('movements').delete().eq('id', last.id); await sendWhatsApp(phone, `🗑 Borré: "${last.description}" ($${Number(last.amount).toLocaleString()})`); }
    else { await sendWhatsApp(phone, `No tienes movimientos para borrar 📭`); }
    return;
  }

  // ═══ GASTO O INGRESO ═══
  const parsed = parseFinancialMessage(lower);
  if (parsed) {
    const { error } = await supabase.from('movements').insert({ user_id: user.id, type: parsed.type, amount: parsed.amount, description: parsed.description, category: parsed.category, source: 'whatsapp' }).select().single();
    if (!error) {
      const { data: movs } = await supabase.from('movements').select('type, amount').eq('user_id', user.id);
      const bal = (movs||[]).reduce((s,m) => s + (m.type==='income' ? Number(m.amount) : -Number(m.amount)), 0);
      if (parsed.type === 'income') {
        await sendWhatsApp(phone, `💵 *Ingreso registrado*\n\n📝 ${parsed.description}\n💰 +$${parsed.amount.toLocaleString()}\n📂 ${parsed.category}\n\nBalance: *$${bal.toLocaleString()}* 📊`);
      } else {
        await sendWhatsApp(phone, `💸 *Gasto registrado*\n\n📝 ${parsed.description}\n💰 -$${parsed.amount.toLocaleString()}\n📂 ${parsed.category}\n\nTe queda: *$${bal.toLocaleString()}* ${bal<0?'⚠️':'👍'}`);
      }
    }
    return;
  }

  // ═══ NO ENTENDIÓ ═══
  await sendWhatsApp(phone, `Mmm, no pillé eso 🤔\n\nPrueba:\n💸 _"pagué luz 80mil"_\n💵 _"vendí 350mil"_\n📊 _"cómo voy?"_\n🔐 _"pin"_\n\nO escribe *ayuda*`);
}

// ══════ PARSER FINANCIERO ══════
function parseFinancialMessage(text) {
  let n = text.replace(/(\d+)\s*mil/gi, (_,x) => String(Number(x)*1000)).replace(/(\d+\.?\d*)\s*m(?:illones?)?/gi, (_,x) => String(Number(x)*1000000)).replace(/(\d+)k/gi, (_,x) => String(Number(x)*1000));
  const amtMatch = n.match(/\$?\s*([\d,.]+)/);
  if (!amtMatch) return null;
  const amount = parseFloat(amtMatch[1].replace(/[,.]/g, ''));
  if (!amount || amount <= 0) return null;
  const incWords = ['vendí','vendi','cobré','cobre','ingreso','me pagaron','recibí','recibi','venta','gané','gane','salario','sueldo'];
  let type = 'expense';
  for (const w of incWords) { if (n.includes(w)) { type = 'income'; break; } }
  let desc = n.replace(/\$?\s*[\d,.]+/g, '').replace(/pagué|pague|gasté|gaste|compré|compre|vendí|vendi|cobré|cobre|ingreso|me pagaron|recibí|recibi|gané|gane/gi, '').replace(/^\s*(de|en|por|el|la|un|una)\s+/i, '').trim();
  if (!desc) desc = type === 'income' ? 'Ingreso' : 'Gasto';
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

// Listar todos los usuarios con conteo de movimientos
app.get('/api/admin/users', verifyAdmin, async (req, res) => {
  try {
    const { data: users } = await supabase.from('users').select('*').order('created_at', { ascending: false });
    if (!users) return res.json({ ok: true, users: [] });

    // Para cada usuario, contar movimientos y calcular volumen
    const enriched = await Promise.all(users.map(async u => {
      const { data: movs } = await supabase.from('movements').select('type, amount').eq('user_id', u.id);
      const count = (movs || []).length;
      const volume = (movs || []).reduce((s, m) => s + Number(m.amount), 0);
      const { pin: _, ...safeUser } = u;
      return { ...safeUser, movement_count: count, total_volume: volume };
    }));

    res.json({ ok: true, users: enriched });
  } catch (err) { res.status(500).json({ error: 'Error al obtener usuarios' }); }
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

// ══════ INICIAR ══════
app.listen(PORT, () => {
  console.log(`⚡ MiCaja Backend v2 en puerto ${PORT}`);
  console.log(`📊 Supabase: ${SUPABASE_URL ? '✅' : '⚠️'}`);
  console.log(`📱 WhatsApp: ${WA_TOKEN ? '✅' : '⚠️ simulado'}`);
});
