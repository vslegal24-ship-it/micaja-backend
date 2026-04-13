// ══════════════════════════════════════
// MiCaja Backend — server.js
// API REST + WhatsApp Webhook
// ══════════════════════════════════════

const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const axios = require('axios');

const app = express();
app.use(cors());
app.use(express.json());

// ═══ CONFIGURACIÓN (variables de entorno en Railway) ═══
const PORT = process.env.PORT || 3000;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const WA_TOKEN = process.env.WA_TOKEN;
const WA_VERIFY_TOKEN = process.env.WA_VERIFY_TOKEN || 'micaja_verify_2026';
const WA_PHONE_ID = process.env.WA_PHONE_ID;

// ═══ SUPABASE CLIENT ═══
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// ══════════════════════════════════════
// HEALTH CHECK
// ══════════════════════════════════════
app.get('/', (req, res) => {
  res.json({ 
    status: 'ok', 
    service: 'MiCaja Backend',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// ══════════════════════════════════════
// AUTH — Registro y Login
// ══════════════════════════════════════

// Registro
app.post('/api/auth/register', async (req, res) => {
  try {
    const { phone, name, pin, plan, partner_phone, partner_name, business_name } = req.body;
    
    if (!phone || !pin || pin.length !== 4) {
      return res.status(400).json({ error: 'Teléfono y PIN de 4 dígitos requeridos' });
    }

    // Verificar si ya existe
    const { data: existing } = await supabase
      .from('users')
      .select('id')
      .eq('phone', phone)
      .single();

    if (existing) {
      return res.status(409).json({ error: 'Este número ya tiene cuenta' });
    }

    const { data, error } = await supabase
      .from('users')
      .insert({ phone, name, pin, plan: plan || 'personal', partner_phone, partner_name, business_name })
      .select()
      .single();

    if (error) throw error;

    // No devolver el PIN
    const { pin: _, ...user } = data;
    res.json({ ok: true, user });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Error al registrar' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, pin } = req.body;

    if (!phone || !pin) {
      return res.status(400).json({ error: 'Teléfono y PIN requeridos' });
    }

    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('phone', phone)
      .eq('pin', pin)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: 'Número o PIN incorrecto' });
    }

    const { pin: _, ...safeUser } = user;
    res.json({ ok: true, user: safeUser });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Error al ingresar' });
  }
});

// Reset PIN (genera nuevo y lo envía por WhatsApp)
app.post('/api/auth/reset-pin', async (req, res) => {
  try {
    const { phone } = req.body;
    
    const { data: user } = await supabase
      .from('users')
      .select('id, name')
      .eq('phone', phone)
      .single();

    if (!user) {
      return res.status(404).json({ error: 'No hay cuenta con ese número' });
    }

    const newPin = String(Math.floor(1000 + Math.random() * 9000));
    
    await supabase
      .from('users')
      .update({ pin: newPin })
      .eq('id', user.id);

    // Enviar por WhatsApp
    if (WA_TOKEN && WA_PHONE_ID) {
      await sendWhatsApp(phone, `🔐 *MiCaja* — Tu nuevo PIN es: *${newPin}*\n\nCámbialo cuando ingreses.`);
    }

    res.json({ ok: true, message: 'Nuevo PIN enviado por WhatsApp' });
  } catch (err) {
    console.error('Reset PIN error:', err);
    res.status(500).json({ error: 'Error al restablecer PIN' });
  }
});

// ══════════════════════════════════════
// MOVIMIENTOS — CRUD
// ══════════════════════════════════════

// Obtener movimientos de un usuario
app.get('/api/movements/:userId', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('movements')
      .select('*')
      .eq('user_id', req.params.userId)
      .order('date', { ascending: false })
      .limit(100);

    if (error) throw error;
    res.json({ ok: true, movements: data });
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener movimientos' });
  }
});

// Crear movimiento
app.post('/api/movements', async (req, res) => {
  try {
    const { user_id, type, amount, description, category, who, shared, note, date, source } = req.body;

    if (!user_id || !type || !amount || !description) {
      return res.status(400).json({ error: 'Campos requeridos: user_id, type, amount, description' });
    }

    // Auto-categorizar si no viene categoría
    const finalCategory = category || autoCategory(description, type);

    const { data, error } = await supabase
      .from('movements')
      .insert({ 
        user_id, type, amount, description, 
        category: finalCategory, who, shared, note,
        date: date || new Date().toISOString().split('T')[0],
        source: source || 'web'
      })
      .select()
      .single();

    if (error) throw error;
    res.json({ ok: true, movement: data });
  } catch (err) {
    console.error('Create movement error:', err);
    res.status(500).json({ error: 'Error al crear movimiento' });
  }
});

// Eliminar movimiento
app.delete('/api/movements/:id', async (req, res) => {
  try {
    const { error } = await supabase
      .from('movements')
      .delete()
      .eq('id', req.params.id);

    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Error al eliminar' });
  }
});

// Resumen financiero
app.get('/api/summary/:userId', async (req, res) => {
  try {
    const { data: movs } = await supabase
      .from('movements')
      .select('*')
      .eq('user_id', req.params.userId);

    const income = (movs || []).filter(m => m.type === 'income').reduce((s, m) => s + Number(m.amount), 0);
    const expense = (movs || []).filter(m => m.type === 'expense').reduce((s, m) => s + Number(m.amount), 0);
    const balance = income - expense;

    // Desglose por categoría
    const byCategory = {};
    (movs || []).forEach(m => {
      if (!byCategory[m.category]) byCategory[m.category] = { income: 0, expense: 0 };
      byCategory[m.category][m.type] += Number(m.amount);
    });

    res.json({ ok: true, summary: { income, expense, balance, count: (movs || []).length, byCategory } });
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener resumen' });
  }
});

// ══════════════════════════════════════
// VIAJES
// ══════════════════════════════════════

// Crear viaje
app.post('/api/trips', async (req, res) => {
  try {
    const { user_id, name, members } = req.body;

    const { data: trip, error } = await supabase
      .from('trips')
      .insert({ user_id, name })
      .select()
      .single();

    if (error) throw error;

    // Agregar miembros
    if (members && members.length > 0) {
      await supabase
        .from('trip_members')
        .insert(members.map(m => ({ trip_id: trip.id, name: m })));
    }

    res.json({ ok: true, trip });
  } catch (err) {
    res.status(500).json({ error: 'Error al crear viaje' });
  }
});

// Obtener viajes de usuario
app.get('/api/trips/:userId', async (req, res) => {
  try {
    const { data } = await supabase
      .from('trips')
      .select('*, trip_members(*), trip_expenses(*)')
      .eq('user_id', req.params.userId)
      .order('created_at', { ascending: false });

    res.json({ ok: true, trips: data || [] });
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener viajes' });
  }
});

// Agregar gasto de viaje
app.post('/api/trips/:tripId/expenses', async (req, res) => {
  try {
    const { description, amount, category, payer, split_between } = req.body;

    const { data, error } = await supabase
      .from('trip_expenses')
      .insert({ 
        trip_id: req.params.tripId, description, amount, 
        category: category || 'General', payer, split_between 
      })
      .select()
      .single();

    if (error) throw error;
    res.json({ ok: true, expense: data });
  } catch (err) {
    res.status(500).json({ error: 'Error al agregar gasto' });
  }
});

// Calcular deudas del viaje
app.get('/api/trips/:tripId/balance', async (req, res) => {
  try {
    const { data: expenses } = await supabase
      .from('trip_expenses')
      .select('*')
      .eq('trip_id', req.params.tripId);

    const { data: members } = await supabase
      .from('trip_members')
      .select('*')
      .eq('trip_id', req.params.tripId);

    // Calcular balance
    const balances = {};
    (members || []).forEach(m => { balances[m.name] = 0; });

    (expenses || []).forEach(exp => {
      const share = exp.amount / exp.split_between.length;
      balances[exp.payer] = (balances[exp.payer] || 0) + exp.amount;
      exp.split_between.forEach(name => {
        balances[name] = (balances[name] || 0) - share;
      });
    });

    // Simplificar deudas
    const debts = [];
    const debtors = Object.entries(balances).filter(([_, v]) => v < 0).sort((a, b) => a[1] - b[1]);
    const creditors = Object.entries(balances).filter(([_, v]) => v > 0).sort((a, b) => b[1] - a[1]);

    let i = 0, j = 0;
    while (i < debtors.length && j < creditors.length) {
      const amount = Math.min(-debtors[i][1], creditors[j][1]);
      if (amount > 0) {
        debts.push({ from: debtors[i][0], to: creditors[j][0], amount: Math.round(amount) });
      }
      debtors[i][1] += amount;
      creditors[j][1] -= amount;
      if (Math.abs(debtors[i][1]) < 1) i++;
      if (Math.abs(creditors[j][1]) < 1) j++;
    }

    res.json({ ok: true, balances, debts, total: (expenses || []).reduce((s, e) => s + Number(e.amount), 0) });
  } catch (err) {
    res.status(500).json({ error: 'Error al calcular balance' });
  }
});

// ══════════════════════════════════════
// WHATSAPP WEBHOOK
// ══════════════════════════════════════

// Verificación del webhook (Meta lo requiere)
app.get('/webhook', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode === 'subscribe' && token === WA_VERIFY_TOKEN) {
    console.log('✅ Webhook verificado');
    res.status(200).send(challenge);
  } else {
    res.sendStatus(403);
  }
});

// Recibir mensajes de WhatsApp
app.post('/webhook', async (req, res) => {
  try {
    const body = req.body;

    if (body.object !== 'whatsapp_business_account') {
      return res.sendStatus(404);
    }

    const entry = body.entry?.[0];
    const changes = entry?.changes?.[0];
    const messages = changes?.value?.messages;

    if (!messages || messages.length === 0) {
      return res.sendStatus(200);
    }

    const msg = messages[0];
    const from = msg.from; // Número del usuario
    const text = msg.text?.body?.trim();

    if (!text) return res.sendStatus(200);

    console.log(`📱 WhatsApp de ${from}: ${text}`);

    // Procesar mensaje
    await processWhatsAppMessage(from, text);

    res.sendStatus(200);
  } catch (err) {
    console.error('Webhook error:', err);
    res.sendStatus(200);
  }
});

// ══════════════════════════════════════
// PROCESAR MENSAJES DE WHATSAPP
// ══════════════════════════════════════
async function processWhatsAppMessage(phone, text) {
  // Buscar usuario
  let { data: user } = await supabase
    .from('users')
    .select('*')
    .eq('phone', phone)
    .single();

  const lower = text.toLowerCase().trim();

  // Si no tiene cuenta
  if (!user) {
    await sendWhatsApp(phone, 
      `👋 ¡Hola! Soy *MiCaja*, tu asistente financiero.\n\n` +
      `Aún no tienes cuenta. Regístrate gratis en:\n` +
      `🌐 inmovak.com\n\n` +
      `O escribe *registrar* para crear tu cuenta aquí.`
    );
    return;
  }

  // Comandos especiales
  if (lower === 'hola' || lower === 'hi' || lower === 'inicio') {
    await sendWhatsApp(phone,
      `👋 ¡Hola ${user.name || ''}! Soy *MiCaja* ⚡\n\n` +
      `Escríbeme así:\n` +
      `💸 *"pagué luz 80mil"* → registra gasto\n` +
      `💵 *"vendí 350mil"* → registra ingreso\n` +
      `📊 *"resumen"* → tu balance\n` +
      `📄 *"informe"* → PDF del mes\n` +
      `❓ *"ayuda"* → ver todos los comandos`
    );
    return;
  }

  if (lower === 'ayuda' || lower === 'help') {
    await sendWhatsApp(phone,
      `📋 *Comandos de MiCaja:*\n\n` +
      `💸 "pagué [desc] [monto]"\n` +
      `💵 "vendí/ingreso [monto]"\n` +
      `📊 "resumen" o "cuánto llevo"\n` +
      `📄 "informe" → PDF del mes\n` +
      `🗑 "borrar último"\n` +
      `❓ "ayuda" → este mensaje`
    );
    return;
  }

  if (lower === 'resumen' || lower === 'cuánto llevo' || lower === 'cuanto llevo' || lower === 'balance') {
    const { data: movs } = await supabase
      .from('movements')
      .select('*')
      .eq('user_id', user.id);

    const inc = (movs || []).filter(m => m.type === 'income').reduce((s, m) => s + Number(m.amount), 0);
    const exp = (movs || []).filter(m => m.type === 'expense').reduce((s, m) => s + Number(m.amount), 0);

    await sendWhatsApp(phone,
      `📊 *Resumen de ${user.name || 'tu cuenta'}:*\n\n` +
      `💵 Ingresos: $${inc.toLocaleString()}\n` +
      `💸 Gastos: $${exp.toLocaleString()}\n` +
      `${inc - exp >= 0 ? '✅' : '⚠️'} Balance: $${(inc - exp).toLocaleString()}\n` +
      `📋 Movimientos: ${(movs || []).length}`
    );
    return;
  }

  if (lower === 'borrar último' || lower === 'borrar ultimo') {
    const { data: last } = await supabase
      .from('movements')
      .select('id, description, amount')
      .eq('user_id', user.id)
      .order('created_at', { ascending: false })
      .limit(1)
      .single();

    if (last) {
      await supabase.from('movements').delete().eq('id', last.id);
      await sendWhatsApp(phone, `🗑 Eliminado: "${last.description}" por $${Number(last.amount).toLocaleString()}`);
    } else {
      await sendWhatsApp(phone, `No hay movimientos para borrar.`);
    }
    return;
  }

  // ═══ INTERPRETAR GASTO O INGRESO (IA simple) ═══
  const parsed = parseFinancialMessage(lower);
  
  if (parsed) {
    const { data: mov, error } = await supabase
      .from('movements')
      .insert({
        user_id: user.id,
        type: parsed.type,
        amount: parsed.amount,
        description: parsed.description,
        category: parsed.category,
        source: 'whatsapp'
      })
      .select()
      .single();

    if (!error) {
      const emoji = parsed.type === 'income' ? '💵' : '💸';
      const label = parsed.type === 'income' ? 'Ingreso' : 'Gasto';
      
      // Obtener balance actual
      const { data: movs } = await supabase
        .from('movements')
        .select('type, amount')
        .eq('user_id', user.id);

      const bal = (movs || []).reduce((s, m) => s + (m.type === 'income' ? Number(m.amount) : -Number(m.amount)), 0);

      await sendWhatsApp(phone,
        `✅ *${label} registrado*\n` +
        `${emoji} ${parsed.description} — $${parsed.amount.toLocaleString()}\n` +
        `📂 ${parsed.category}\n` +
        `💰 Balance: $${bal.toLocaleString()}`
      );
    }
    return;
  }

  // No se entendió
  await sendWhatsApp(phone,
    `🤔 No entendí. Intenta así:\n\n` +
    `💸 *"pagué luz 80000"*\n` +
    `💵 *"vendí 350000"*\n` +
    `📊 *"resumen"*\n` +
    `❓ *"ayuda"*`
  );
}

// ══════════════════════════════════════
// PARSER DE MENSAJES FINANCIEROS
// ══════════════════════════════════════
function parseFinancialMessage(text) {
  // Normalizar: "80mil" → "80000", "1.5M" → "1500000"
  let normalized = text
    .replace(/(\d+)\s*mil/gi, (_, n) => String(Number(n) * 1000))
    .replace(/(\d+\.?\d*)\s*m(?:illones?)?/gi, (_, n) => String(Number(n) * 1000000))
    .replace(/(\d+)k/gi, (_, n) => String(Number(n) * 1000));

  // Buscar monto
  const amountMatch = normalized.match(/\$?\s*([\d,.]+)/);
  if (!amountMatch) return null;
  
  const amount = parseFloat(amountMatch[1].replace(/[,.]/g, ''));
  if (!amount || amount <= 0) return null;

  // Determinar tipo
  const expenseWords = ['pagué', 'pague', 'gasté', 'gaste', 'compré', 'compre', 'pagó', 'pago de', 'gasto'];
  const incomeWords = ['vendí', 'vendi', 'cobré', 'cobre', 'ingreso', 'me pagaron', 'recibí', 'recibi', 'venta'];

  let type = 'expense'; // default
  for (const w of incomeWords) {
    if (normalized.includes(w)) { type = 'income'; break; }
  }

  // Extraer descripción (quitar el monto y palabras clave)
  let desc = normalized
    .replace(/\$?\s*[\d,.]+/g, '')
    .replace(/pagué|pague|gasté|gaste|compré|compre|vendí|vendi|cobré|cobre|ingreso|me pagaron|recibí|recibi/gi, '')
    .replace(/^\s*(de|en|por|el|la|un|una)\s+/i, '')
    .trim();

  if (!desc) desc = type === 'income' ? 'Ingreso' : 'Gasto';
  desc = desc.charAt(0).toUpperCase() + desc.slice(1);

  // Auto-categorizar
  const category = autoCategory(desc, type);

  return { type, amount, description: desc, category };
}

// ══════════════════════════════════════
// AUTO-CATEGORIZACIÓN
// ══════════════════════════════════════
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

// ══════════════════════════════════════
// ENVIAR MENSAJE POR WHATSAPP
// ══════════════════════════════════════
async function sendWhatsApp(to, message) {
  if (!WA_TOKEN || !WA_PHONE_ID) {
    console.log(`[WA SIMULADO] → ${to}: ${message}`);
    return;
  }

  try {
    // Formatear número (quitar + y espacios)
    const phone = to.replace(/[+\s-]/g, '');
    
    await axios.post(
      `https://graph.facebook.com/v18.0/${WA_PHONE_ID}/messages`,
      {
        messaging_product: 'whatsapp',
        to: phone,
        type: 'text',
        text: { body: message }
      },
      {
        headers: {
          'Authorization': `Bearer ${WA_TOKEN}`,
          'Content-Type': 'application/json'
        }
      }
    );
    console.log(`✅ WA enviado a ${phone}`);
  } catch (err) {
    console.error('Error enviando WA:', err.response?.data || err.message);
  }
}

// ══════════════════════════════════════
// INICIAR SERVIDOR
// ══════════════════════════════════════
app.listen(PORT, () => {
  console.log(`⚡ MiCaja Backend corriendo en puerto ${PORT}`);
  console.log(`📊 Supabase: ${SUPABASE_URL ? 'Conectado' : '⚠️ Sin configurar'}`);
  console.log(`📱 WhatsApp: ${WA_TOKEN ? 'Configurado' : '⚠️ Sin configurar (modo simulado)'}`);
});
