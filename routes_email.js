// ════════════════════════════════════════════════════════════
// routes_email.js — Komunity Hub Phase 1 Email Marketing
// ────────────────────────────────────────────────────────────
// Module Express modulaire pour gérer:
//   - Listes de diffusion (création, contacts, import bulk)
//   - Templates email réutilisables
//   - Campagnes (brouillon → test → envoi)
//   - Envoi via Resend (avec personnalisation {{first_name}})
//   - Webhook Resend (ouvertures, clics, bounces)
//   - Désabonnement (lien public, RGPD-compliant)
//   - Stats globales et par campagne
// ────────────────────────────────────────────────────────────
// À monter dans server.js avec:
//   const emailRoutes = require('./routes_email');
//   app.use('/api/email', emailRoutes);
// ════════════════════════════════════════════════════════════

const express = require('express');
const crypto = require('crypto');
const router = express.Router();

// ────────────── CONFIG (réutilise les vars d'env de server.js)
const CONFIG = {
  SUPABASE_URL: process.env.SUPABASE_URL,
  SUPABASE_SERVICE_KEY: process.env.SUPABASE_SERVICE_KEY,
  RESEND_API_KEY: process.env.RESEND_API_KEY,
  RESEND_WEBHOOK_SECRET: process.env.RESEND_WEBHOOK_SECRET, // optionnel mais recommandé
  JWT_SECRET: process.env.JWT_SECRET,
  BASE_URL: process.env.BASE_URL || 'https://api.samabot.app',
  DEFAULT_FROM: process.env.KOMUNITY_FROM_EMAIL || 'Komunity SN <noreply@komunitysn.com>'
};

// ────────────── DB HELPER (clone du pattern Supabase REST de server.js)
async function sb(table, method = 'GET', data = null, query = '') {
  const key = CONFIG.SUPABASE_SERVICE_KEY;
  const res = await fetch(`${CONFIG.SUPABASE_URL}/rest/v1/${table}${query}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      'apikey': key,
      'Authorization': `Bearer ${key}`,
      'Prefer': 'return=representation'
    },
    body: data ? JSON.stringify(data) : undefined
  });
  const text = await res.text();
  return text ? JSON.parse(text) : null;
}
const db = {
  select: (t, q = '') => sb(t, 'GET', null, q),
  insert: (t, d) => sb(t, 'POST', d),
  update: (t, d, q) => sb(t, 'PATCH', d, q),
  delete: (t, q) => sb(t, 'DELETE', null, q)
};

// ────────────── AUTH (JWT, même format que server.js)
function verifyToken(token) {
  if (!token) return null;
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [header, payload, sig] = parts;
    const expected = crypto.createHmac('sha256', CONFIG.JWT_SECRET).update(header + '.' + payload).digest('base64url');
    if (sig !== expected) return null;
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (data.exp < Math.floor(Date.now() / 1000)) return null;
    return data.userId;
  } catch (e) { return null; }
}

async function getUserRole(userId) {
  try {
    const rows = await db.select('user_roles', `?user_id=eq.${userId}&select=role&limit=1`);
    return rows?.[0]?.role || null;
  } catch (e) { return null; }
}

async function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const userId = verifyToken(token);
  if (!userId) return res.status(401).json({ error: 'Non autorisé — token manquant ou invalide' });
  req.userId = userId;
  req.userRole = await getUserRole(userId);
  next();
}

function requireRole(...allowed) {
  return (req, res, next) => {
    if (!allowed.includes(req.userRole)) {
      return res.status(403).json({ error: `Permission refusée — rôle ${allowed.join(' ou ')} requis` });
    }
    next();
  };
}

// ════════════════════════════════════════════════════════════
// LISTS — Listes de diffusion
// ════════════════════════════════════════════════════════════
router.get('/lists', authMiddleware, async (req, res) => {
  try {
    const lists = await db.select('email_lists', '?order=created_at.desc');
    res.json(lists || []);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/lists', authMiddleware, requireRole('superadmin', 'agency_admin'), async (req, res) => {
  try {
    const { name, description, client_id } = req.body;
    if (!name) return res.status(400).json({ error: 'name requis' });
    const list = await db.insert('email_lists', {
      name,
      description: description || null,
      client_id: client_id || null,
      owner_id: req.userId,
      contact_count: 0
    });
    res.json({ success: true, list: list?.[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.delete('/lists/:id', authMiddleware, requireRole('superadmin', 'agency_admin'), async (req, res) => {
  try {
    await db.delete('email_lists', `?id=eq.${req.params.id}`);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════
// CONTACTS — gestion par liste, avec import bulk
// ════════════════════════════════════════════════════════════
router.get('/contacts', authMiddleware, async (req, res) => {
  try {
    const listId = req.query.list_id;
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const q = listId
      ? `?list_id=eq.${listId}&status=neq.deleted&order=created_at.desc&limit=${limit}`
      : `?status=neq.deleted&order=created_at.desc&limit=${limit}`;
    const contacts = await db.select('email_contacts', q);
    res.json(contacts || []);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/contacts', authMiddleware, async (req, res) => {
  try {
    const { email, first_name, last_name, list_id, tags } = req.body;
    if (!email || !list_id) return res.status(400).json({ error: 'email et list_id requis' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Email invalide' });

    const normalized = email.toLowerCase().trim();
    const existing = await db.select('email_contacts', `?email=eq.${encodeURIComponent(normalized)}&list_id=eq.${list_id}&limit=1`);
    if (existing?.length) return res.status(409).json({ error: 'Contact déjà présent dans cette liste' });

    const contact = await db.insert('email_contacts', {
      email: normalized,
      first_name: first_name || null,
      last_name: last_name || null,
      list_id,
      tags: tags || [],
      status: 'subscribed',
      unsubscribe_token: crypto.randomBytes(16).toString('hex'),
      created_at: new Date().toISOString()
    });
    res.json({ success: true, contact: contact?.[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/contacts/bulk', authMiddleware, async (req, res) => {
  try {
    const { list_id, contacts } = req.body;
    if (!list_id || !Array.isArray(contacts)) return res.status(400).json({ error: 'list_id et contacts (array) requis' });
    if (contacts.length > 5000) return res.status(400).json({ error: 'Max 5000 contacts par batch' });

    let added = 0, skipped = 0, errors = 0;
    for (const c of contacts) {
      if (!c.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(c.email)) { skipped++; continue; }
      const normalized = c.email.toLowerCase().trim();
      try {
        const existing = await db.select('email_contacts', `?email=eq.${encodeURIComponent(normalized)}&list_id=eq.${list_id}&limit=1`);
        if (existing?.length) { skipped++; continue; }
        await db.insert('email_contacts', {
          email: normalized,
          first_name: c.first_name || c.firstname || null,
          last_name: c.last_name || c.lastname || null,
          list_id,
          tags: c.tags || [],
          status: 'subscribed',
          unsubscribe_token: crypto.randomBytes(16).toString('hex'),
          created_at: new Date().toISOString()
        });
        added++;
      } catch (e) { errors++; }
    }
    res.json({ success: true, added, skipped_duplicates: skipped, errors, total_received: contacts.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.delete('/contacts/:id', authMiddleware, async (req, res) => {
  try {
    // Soft delete pour garder l'historique
    await db.update('email_contacts', { status: 'deleted' }, `?id=eq.${req.params.id}`);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════
// TEMPLATES — emails réutilisables
// ════════════════════════════════════════════════════════════
router.get('/templates', authMiddleware, async (req, res) => {
  try {
    const tpls = await db.select('email_templates', '?order=created_at.desc');
    res.json(tpls || []);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/templates', authMiddleware, requireRole('superadmin', 'agency_admin'), async (req, res) => {
  try {
    const { name, subject, html, text } = req.body;
    if (!name || !html) return res.status(400).json({ error: 'name et html requis' });
    const tpl = await db.insert('email_templates', {
      name,
      subject: subject || '',
      html,
      text: text || null,
      owner_id: req.userId,
      is_global: false,
      created_at: new Date().toISOString()
    });
    res.json({ success: true, template: tpl?.[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.patch('/templates/:id', authMiddleware, requireRole('superadmin', 'agency_admin'), async (req, res) => {
  try {
    const allowed = ['name', 'subject', 'html', 'text'];
    const updates = {};
    for (const k of allowed) if (req.body[k] !== undefined) updates[k] = req.body[k];
    updates.updated_at = new Date().toISOString();
    await db.update('email_templates', updates, `?id=eq.${req.params.id}`);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.delete('/templates/:id', authMiddleware, requireRole('superadmin', 'agency_admin'), async (req, res) => {
  try {
    await db.delete('email_templates', `?id=eq.${req.params.id}`);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════
// CAMPAIGNS — création, modification, envoi
// ════════════════════════════════════════════════════════════
router.get('/campaigns', authMiddleware, async (req, res) => {
  try {
    const camps = await db.select('email_campaigns', '?order=created_at.desc&limit=100');
    res.json(camps || []);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/campaigns', authMiddleware, requireRole('superadmin', 'agency_admin', 'agency_member'), async (req, res) => {
  try {
    const { name, subject, html, list_id, template_id, from_name, from_email, client_id } = req.body;
    if (!name) return res.status(400).json({ error: 'name requis' });
    const camp = await db.insert('email_campaigns', {
      name,
      subject: subject || '',
      html: html || '',
      list_id: list_id || null,
      template_id: template_id || null,
      client_id: client_id || null,
      from_name: from_name || 'Komunity SN',
      from_email: from_email || 'noreply@komunitysn.com',
      status: 'draft',
      owner_id: req.userId,
      created_at: new Date().toISOString()
    });
    res.json({ success: true, campaign: camp?.[0] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.patch('/campaigns/:id', authMiddleware, requireRole('superadmin', 'agency_admin', 'agency_member'), async (req, res) => {
  try {
    const allowed = ['name', 'subject', 'html', 'list_id', 'template_id', 'from_name', 'from_email'];
    const updates = {};
    for (const k of allowed) if (req.body[k] !== undefined) updates[k] = req.body[k];
    updates.updated_at = new Date().toISOString();
    await db.update('email_campaigns', updates, `?id=eq.${req.params.id}`);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.delete('/campaigns/:id', authMiddleware, requireRole('superadmin', 'agency_admin'), async (req, res) => {
  try {
    const camps = await db.select('email_campaigns', `?id=eq.${req.params.id}&limit=1`);
    if (!camps?.[0]) return res.status(404).json({ error: 'Campagne introuvable' });
    if (camps[0].status === 'sent' || camps[0].status === 'sending') {
      return res.status(400).json({ error: 'Impossible de supprimer une campagne déjà envoyée ou en cours' });
    }
    await db.delete('email_campaigns', `?id=eq.${req.params.id}`);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Envoyer un email TEST (à une seule adresse, pour vérifier le rendu)
router.post('/campaigns/:id/test', authMiddleware, async (req, res) => {
  try {
    const { test_email } = req.body;
    if (!test_email) return res.status(400).json({ error: 'test_email requis' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(test_email)) return res.status(400).json({ error: 'Email invalide' });

    const camps = await db.select('email_campaigns', `?id=eq.${req.params.id}&limit=1`);
    const camp = camps?.[0];
    if (!camp) return res.status(404).json({ error: 'Campagne introuvable' });
    if (!camp.html) return res.status(400).json({ error: 'Contenu HTML manquant' });

    // Pas de tracking, pas d'unsubscribe sur le test
    const result = await sendViaResend({
      from: `${camp.from_name} <${camp.from_email}>`,
      to: test_email,
      subject: '[TEST] ' + camp.subject,
      html: camp.html
    });
    res.json({ success: true, sent_to: test_email, resend_id: result?.id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Envoyer la campagne à toute la liste (envoi async en arrière-plan)
router.post('/campaigns/:id/send', authMiddleware, requireRole('superadmin', 'agency_admin'), async (req, res) => {
  try {
    const camps = await db.select('email_campaigns', `?id=eq.${req.params.id}&limit=1`);
    const camp = camps?.[0];
    if (!camp) return res.status(404).json({ error: 'Campagne introuvable' });
    if (camp.status === 'sent' || camp.status === 'sending') {
      return res.status(400).json({ error: 'Campagne déjà envoyée ou en cours d\'envoi' });
    }
    if (!camp.list_id) return res.status(400).json({ error: 'Liste destinataire requise' });
    if (!camp.html || !camp.subject) return res.status(400).json({ error: 'Sujet et contenu HTML requis' });

    const contacts = await db.select('email_contacts', `?list_id=eq.${camp.list_id}&status=eq.subscribed&limit=10000`);
    if (!contacts?.length) return res.status(400).json({ error: 'Aucun contact actif dans la liste' });

    // Marquer comme "sending"
    await db.update('email_campaigns', {
      status: 'sending',
      sent_at: new Date().toISOString()
    }, `?id=eq.${camp.id}`);

    // Réponse immédiate, envoi en background
    res.json({
      success: true,
      queued: contacts.length,
      message: `${contacts.length} emails en cours d'envoi en arrière-plan`
    });

    // Background processing (ne bloque pas la réponse HTTP)
    sendCampaignBackground(camp, contacts).catch(e => console.error('❌ Send campaign error:', e.message));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ────────────── Helper: envoi en arrière-plan
async function sendCampaignBackground(camp, contacts) {
  let sent = 0, failed = 0;
  console.log(`📧 Début envoi campagne ${camp.id} → ${contacts.length} contacts`);

  for (const c of contacts) {
    try {
      const html = injectTrackingAndUnsubscribe(camp.html, c, camp.id);
      const result = await sendViaResend({
        from: `${camp.from_name} <${camp.from_email}>`,
        to: c.email,
        subject: camp.subject,
        html
      });
      await db.insert('email_sends', {
        campaign_id: camp.id,
        contact_id: c.id,
        email: c.email,
        status: 'sent',
        resend_id: result?.id || null,
        sent_at: new Date().toISOString()
      });
      sent++;
    } catch (e) {
      await db.insert('email_sends', {
        campaign_id: camp.id,
        contact_id: c.id,
        email: c.email,
        status: 'failed',
        error: (e.message || 'unknown').substring(0, 200),
        sent_at: new Date().toISOString()
      }).catch(() => {});
      failed++;
    }
    // Rate limit Resend: 10 emails/sec recommandé sur plan gratuit
    if ((sent + failed) % 10 === 0) await new Promise(r => setTimeout(r, 1000));
  }

  await db.update('email_campaigns', {
    status: 'sent',
    sent_count: sent,
    failed_count: failed,
    completed_at: new Date().toISOString()
  }, `?id=eq.${camp.id}`);

  console.log(`✅ Campagne ${camp.id} terminée: ${sent} envoyés, ${failed} échecs`);
}

// ────────────── Helper: personnalisation + tracking + footer désabonnement
function injectTrackingAndUnsubscribe(html, contact, campaignId) {
  const unsubUrl = `${CONFIG.BASE_URL}/api/email/unsubscribe?token=${contact.unsubscribe_token}`;
  const footer = `
<hr style="margin:32px 0 12px;border:none;border-top:1px solid #e5e7eb">
<p style="font-size:11px;color:#888;text-align:center;font-family:-apple-system,sans-serif;line-height:1.5">
  Vous recevez cet email parce que vous êtes inscrit à notre liste.<br>
  <a href="${unsubUrl}" style="color:#888;text-decoration:underline">Se désabonner</a>
  &middot; Komunity SN, Dakar, Sénégal
</p>`;

  // Personnalisation merge tags: {{first_name}}, {{last_name}}, {{email}}
  let out = html
    .replace(/\{\{\s*first_name\s*\}\}/gi, contact.first_name || '')
    .replace(/\{\{\s*last_name\s*\}\}/gi, contact.last_name || '')
    .replace(/\{\{\s*email\s*\}\}/gi, contact.email);

  // Inject footer avant </body> si présent
  if (/<\/body>/i.test(out)) {
    out = out.replace(/<\/body>/i, footer + '</body>');
  } else {
    out += footer;
  }
  return out;
}

// ────────────── Helper: envoi Resend
async function sendViaResend({ from, to, subject, html, text }) {
  if (!CONFIG.RESEND_API_KEY) throw new Error('RESEND_API_KEY manquante dans Railway');
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${CONFIG.RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ from, to: [to], subject, html, text })
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.message || data.error?.message || `Resend HTTP ${res.status}`);
  return data;
}

// ════════════════════════════════════════════════════════════
// WEBHOOK Resend — ouvertures, clics, bounces, complaints
// À configurer dans Resend dashboard:
//   URL: https://api.samabot.app/api/email/webhook
//   Events: email.delivered, email.opened, email.clicked, email.bounced, email.complained
// ════════════════════════════════════════════════════════════
router.post('/webhook', async (req, res) => {
  try {
    const event = req.body;
    const eventType = event.type;
    const emailData = event.data || {};

    // TODO: vérification signature Svix (RESEND_WEBHOOK_SECRET) pour la prod
    // Pour MVP on accepte tous les webhooks entrants

    if (emailData.email_id) {
      const sends = await db.select('email_sends', `?resend_id=eq.${emailData.email_id}&limit=1`);
      const send = sends?.[0];
      if (send) {
        // Logger l'event
        await db.insert('email_events', {
          send_id: send.id,
          campaign_id: send.campaign_id,
          contact_id: send.contact_id,
          event_type: eventType,
          metadata: emailData,
          created_at: new Date().toISOString()
        }).catch(() => {});

        // Mettre à jour le statut du send (sauf si déjà à un statut "supérieur")
        const statusMap = {
          'email.delivered': 'delivered',
          'email.opened': 'opened',
          'email.clicked': 'clicked',
          'email.bounced': 'bounced',
          'email.complained': 'complained'
        };
        if (statusMap[eventType]) {
          await db.update('email_sends', { status: statusMap[eventType] }, `?id=eq.${send.id}`);
        }

        // Auto-unsubscribe sur bounce/complaint
        if (eventType === 'email.bounced' || eventType === 'email.complained') {
          await db.update('email_contacts', {
            status: 'unsubscribed',
            unsubscribed_at: new Date().toISOString(),
            unsubscribe_reason: eventType
          }, `?id=eq.${send.contact_id}`).catch(() => {});
        }
      }
    }

    res.json({ received: true });
  } catch (e) {
    console.error('❌ Webhook error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ════════════════════════════════════════════════════════════
// UNSUBSCRIBE — lien public (pas d'auth), RGPD obligatoire
// ════════════════════════════════════════════════════════════
router.get('/unsubscribe', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).send('Lien invalide');
    const contacts = await db.select('email_contacts', `?unsubscribe_token=eq.${token}&limit=1`);
    const contact = contacts?.[0];
    if (!contact) return res.status(404).send('Contact introuvable');

    await db.update('email_contacts', {
      status: 'unsubscribed',
      unsubscribed_at: new Date().toISOString(),
      unsubscribe_reason: 'user_action'
    }, `?id=eq.${contact.id}`);

    res.send(`<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Désabonnement confirmé — Komunity SN</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#fafafa;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.box{background:#fff;border-radius:16px;padding:48px 36px;max-width:480px;width:100%;text-align:center;box-shadow:0 4px 24px rgba(0,0,0,0.06)}
.ico{font-size:48px;margin-bottom:16px;color:#10b981}
h1{font-size:24px;margin-bottom:12px;color:#09090b}
p{color:#52525b;line-height:1.6;font-size:14px}
.email{background:#f4f4f5;padding:8px 14px;border-radius:8px;font-family:monospace;display:inline-block;margin:8px 0;color:#09090b}
.note{margin-top:32px;font-size:12px;color:#a1a1aa}
a{color:#F39200;text-decoration:none}
</style></head>
<body>
<div class="box">
<div class="ico">✓</div>
<h1>Désabonnement confirmé</h1>
<p>L'adresse <span class="email">${contact.email}</span> a bien été retirée de notre liste de diffusion.</p>
<p style="margin-top:12px">Vous ne recevrez plus d'emails de notre part.</p>
<p class="note">Komunity SN &middot; Dakar, Sénégal<br>Une erreur ? <a href="mailto:contact@komunitysn.com">Contactez-nous</a></p>
</div>
</body></html>`);
  } catch (e) {
    console.error('Unsubscribe error:', e.message);
    res.status(500).send('Erreur serveur');
  }
});

// ════════════════════════════════════════════════════════════
// STATS — globales et par campagne
// ════════════════════════════════════════════════════════════
router.get('/stats', authMiddleware, async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 30;
    const since = new Date(Date.now() - days * 86400000).toISOString();

    const [sends, events, lists, camps] = await Promise.all([
      db.select('email_sends', `?sent_at=gte.${since}&select=id,status`),
      db.select('email_events', `?created_at=gte.${since}&select=event_type,contact_id`),
      db.select('email_lists', '?select=id,contact_count'),
      db.select('email_campaigns', `?created_at=gte.${since}&select=id,status`)
    ]);

    const totalSent = (sends || []).length;
    const delivered = (sends || []).filter(s => ['delivered', 'opened', 'clicked'].includes(s.status)).length;
    const opens = (events || []).filter(e => e.event_type === 'email.opened');
    const clicks = (events || []).filter(e => e.event_type === 'email.clicked');
    const bounces = (sends || []).filter(s => s.status === 'bounced').length;
    const uniqueOpens = new Set(opens.map(e => e.contact_id)).size;

    res.json({
      period_days: days,
      total_sent: totalSent,
      delivered,
      unique_opens: uniqueOpens,
      total_clicks: clicks.length,
      total_bounces: bounces,
      open_rate: totalSent ? +(uniqueOpens / totalSent * 100).toFixed(1) : 0,
      click_rate: totalSent ? +(clicks.length / totalSent * 100).toFixed(1) : 0,
      bounce_rate: totalSent ? +(bounces / totalSent * 100).toFixed(1) : 0,
      total_lists: (lists || []).length,
      total_contacts: (lists || []).reduce((s, l) => s + (l.contact_count || 0), 0),
      campaigns_period: (camps || []).length,
      campaigns_by_status: (camps || []).reduce((acc, c) => {
        acc[c.status] = (acc[c.status] || 0) + 1;
        return acc;
      }, {})
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

router.get('/campaigns/:id/stats', authMiddleware, async (req, res) => {
  try {
    const cid = req.params.id;
    const [campRow, sends, events] = await Promise.all([
      db.select('email_campaigns', `?id=eq.${cid}&limit=1`),
      db.select('email_sends', `?campaign_id=eq.${cid}&select=id,contact_id,status`),
      db.select('email_events', `?campaign_id=eq.${cid}&select=event_type,contact_id`)
    ]);
    const camp = campRow?.[0];
    if (!camp) return res.status(404).json({ error: 'Campagne introuvable' });

    const totalSent = (sends || []).length;
    const opens = (events || []).filter(e => e.event_type === 'email.opened');
    const clicks = (events || []).filter(e => e.event_type === 'email.clicked');
    const uniqueOpens = new Set(opens.map(e => e.contact_id)).size;
    const uniqueClicks = new Set(clicks.map(e => e.contact_id)).size;
    const delivered = (sends || []).filter(s => ['delivered', 'opened', 'clicked'].includes(s.status)).length;
    const bounced = (sends || []).filter(s => s.status === 'bounced').length;
    const failed = (sends || []).filter(s => s.status === 'failed').length;

    res.json({
      campaign: {
        id: camp.id,
        name: camp.name,
        subject: camp.subject,
        status: camp.status,
        sent_at: camp.sent_at,
        completed_at: camp.completed_at
      },
      total_sent: totalSent,
      delivered,
      unique_opens: uniqueOpens,
      unique_clicks: uniqueClicks,
      bounced,
      failed,
      open_rate: totalSent ? +(uniqueOpens / totalSent * 100).toFixed(1) : 0,
      click_rate: totalSent ? +(uniqueClicks / totalSent * 100).toFixed(1) : 0,
      bounce_rate: totalSent ? +(bounced / totalSent * 100).toFixed(1) : 0
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════
// HEALTH CHECK module
// ════════════════════════════════════════════════════════════
router.get('/health', (req, res) => {
  res.json({
    module: 'komunity-hub-email',
    version: '1.0.0',
    status: 'active',
    endpoints: {
      lists: ['GET /lists', 'POST /lists', 'DELETE /lists/:id'],
      contacts: ['GET /contacts?list_id=X', 'POST /contacts', 'POST /contacts/bulk', 'DELETE /contacts/:id'],
      templates: ['GET /templates', 'POST /templates', 'PATCH /templates/:id', 'DELETE /templates/:id'],
      campaigns: ['GET /campaigns', 'POST /campaigns', 'PATCH /campaigns/:id', 'DELETE /campaigns/:id', 'POST /campaigns/:id/test', 'POST /campaigns/:id/send'],
      webhook: ['POST /webhook'],
      unsubscribe: ['GET /unsubscribe?token=X'],
      stats: ['GET /stats?days=30', 'GET /campaigns/:id/stats']
    }
  });
});

module.exports = router;
