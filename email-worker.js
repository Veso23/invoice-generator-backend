// ============================================================
// EMAIL WORKER — replaces the N8N timesheet ingestion workflow
// ============================================================
// Polls an IMAP inbox, extracts PDF attachments, uploads them to
// Supabase Storage, extracts text, and calls the local
// /api/timesheets/analyze endpoint (slim/full AI mode).
//
// Designed for zero-intervention BYOC deployments:
//   - All config via env vars (no per-client code changes)
//   - Never crashes the main process; every failure is logged
//   - Idempotent: dedupe by IMAP message-id stored in automation_logs
//   - Bounded retries: after MAX_ATTEMPTS a poison email is logged
//     as skipped and marked seen so it can never wedge the queue
//
// Required env vars (worker stays disabled if missing):
//   IMAP_HOST, IMAP_USER, IMAP_PASSWORD
// Optional:
//   IMAP_PORT (default 993), IMAP_TLS (default true)
//   IMAP_MAILBOX (default INBOX)
//   COMPANY_ID (default: auto-detect if exactly one company exists)
//   EMAIL_POLL_INTERVAL_MINUTES (default 2)
// ============================================================

const { ImapFlow } = require('imapflow');
const { simpleParser } = require('mailparser');
const pdfParse = require('pdf-parse');

const POLL_INTERVAL_MS =
  Math.max(1, parseInt(process.env.EMAIL_POLL_INTERVAL_MINUTES || '2', 10)) * 60 * 1000;
const MAX_ATTEMPTS = 3;
const MAILBOX = process.env.IMAP_MAILBOX || 'INBOX';

// In-memory attempt counter for poison-message protection.
// Resets on process restart — combined with DB dedupe that is safe.
const attemptCounts = new Map();

let running = false;   // prevents overlapping poll cycles
let companyIdCache = null;

function log(...args)  { console.log('[email-worker]', ...args); }
function warn(...args) { console.warn('[email-worker]', ...args); }

// ------------------------------------------------------------
// Bootstrap
// ------------------------------------------------------------
function startEmailWorker({ pool, supabase, port }) {
  const { IMAP_HOST, IMAP_USER, IMAP_PASSWORD } = process.env;

  if (!IMAP_HOST || !IMAP_USER || !IMAP_PASSWORD) {
    log('disabled — set IMAP_HOST, IMAP_USER and IMAP_PASSWORD to enable.');
    return;
  }

  ensureSchema(pool)
    .then(() => {
      log(`enabled — polling ${MAILBOX} on ${IMAP_HOST} every ${POLL_INTERVAL_MS / 60000} min`);
      // First run shortly after boot (lets the HTTP server come up first)
      setTimeout(() => pollSafe(pool, supabase, port), 15 * 1000);
      setInterval(() => pollSafe(pool, supabase, port), POLL_INTERVAL_MS);
    })
    .catch(err => warn('schema init failed, worker disabled:', err.message));
}

async function ensureSchema(pool) {
  await pool.query(`
    ALTER TABLE automation_logs
      ADD COLUMN IF NOT EXISTS message_id VARCHAR(500) DEFAULT NULL
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_automation_logs_message_id
      ON automation_logs (message_id) WHERE message_id IS NOT NULL
  `);
}

// ------------------------------------------------------------
// Poll cycle — never throws
// ------------------------------------------------------------
async function pollSafe(pool, supabase, port) {
  if (running) return; // previous cycle still in progress
  running = true;
  try {
    await poll(pool, supabase, port);
  } catch (err) {
    warn('poll cycle failed:', err.message);
  } finally {
    running = false;
  }
}

async function poll(pool, supabase, port) {
  const client = new ImapFlow({
    host: process.env.IMAP_HOST,
    port: parseInt(process.env.IMAP_PORT || '993', 10),
    secure: process.env.IMAP_TLS !== 'false',
    auth: { user: process.env.IMAP_USER, pass: process.env.IMAP_PASSWORD },
    logger: false,
    socketTimeout: 60 * 1000,
  });

  await client.connect();
  try {
    const lock = await client.getMailboxLock(MAILBOX);
    try {
      const unseen = await client.search({ seen: false });
      if (!unseen || unseen.length === 0) return;

      log(`found ${unseen.length} unseen email(s)`);

      for (const uid of unseen) {
        await processOne(client, uid, pool, supabase, port);
      }
    } finally {
      lock.release();
    }
  } finally {
    await client.logout().catch(() => {});
  }
}

// ------------------------------------------------------------
// Single email — mark seen ONLY once outcome is recorded in DB
// ------------------------------------------------------------
async function processOne(client, uid, pool, supabase, port) {
  let messageId = `uid-${uid}`;
  try {
    const { content } = await client.download(String(uid), undefined, { uid: false });
    const parsed = await simpleParser(content);

    messageId = (parsed.messageId || messageId).trim();

    // ---- Dedupe: already processed in a previous run/cycle? ----
    const dupe = await pool.query(
      'SELECT id FROM automation_logs WHERE message_id = $1 LIMIT 1',
      [messageId]
    );
    if (dupe.rows.length > 0) {
      log(`skip duplicate ${messageId} (log #${dupe.rows[0].id})`);
      await markSeen(client, uid);
      return;
    }

    // ---- Poison-message protection ----
    const attempts = (attemptCounts.get(messageId) || 0) + 1;
    attemptCounts.set(messageId, attempts);
    if (attempts > MAX_ATTEMPTS) {
      warn(`giving up on ${messageId} after ${MAX_ATTEMPTS} attempts`);
      await insertSkipLog(pool, {
        companyId: await resolveCompanyId(pool),
        senderEmail: parsed.from?.value?.[0]?.address || null,
        recipientEmail: parsed.to?.value?.[0]?.address || null,
        messageId,
        notes: `Processing failed ${MAX_ATTEMPTS} times — flagged for manual review. Subject: ${parsed.subject || '(none)'}`,
      });
      await markSeen(client, uid);
      attemptCounts.delete(messageId);
      return;
    }

    const senderEmail = (parsed.from?.value?.[0]?.address || '').toLowerCase().trim();
    const recipientEmail = (parsed.to?.value?.[0]?.address || '').toLowerCase().trim();
    const companyId = await resolveCompanyId(pool);

    // ---- Collect PDF attachments ----
    const pdfs = (parsed.attachments || []).filter(a =>
      a.contentType === 'application/pdf' ||
      (a.filename || '').toLowerCase().endsWith('.pdf')
    );

    // ---- Consultant check (same rule as the old N8N flow) ----
    const consultant = await pool.query(
      `SELECT id FROM consultants
       WHERE deleted_at IS NULL AND company_id = $1 AND LOWER(email) = $2
       LIMIT 1`,
      [companyId, senderEmail]
    );

    if (consultant.rows.length === 0 || pdfs.length === 0) {
      const reason = consultant.rows.length === 0
        ? `Sender not registered as consultant: ${senderEmail}`
        : `No PDF attachments in email: ${parsed.subject || '(no subject)'}`;
      await insertSkipLog(pool, { companyId, senderEmail, recipientEmail, messageId, notes: reason });
      await markSeen(client, uid);
      attemptCounts.delete(messageId);
      log(`skipped ${messageId}: ${reason}`);
      return;
    }

    // ---- Upload PDFs to Supabase Storage + extract text ----
    const ts = new Date().toISOString().replace(/[:.]/g, '').substring(0, 15);
    const emailSlug = senderEmail.replace(/[^a-z0-9]/g, '_');
    const extractedTexts = [];

    for (let i = 0; i < pdfs.length; i++) {
      const a = pdfs[i];
      const safeName = (a.filename || `file_${i + 1}.pdf`).replace(/[^a-zA-Z0-9._-]/g, '_');
      const storageName = `${emailSlug}_${ts}_${i + 1}_${safeName}`;

      const { error: upErr } = await supabase.storage
        .from('timesheets')
        .upload(storageName, a.content, { contentType: 'application/pdf', upsert: true });
      if (upErr) throw new Error(`storage upload failed for ${safeName}: ${upErr.message}`);

      const { data: urlData } = supabase.storage.from('timesheets').getPublicUrl(storageName);

      let text = '';
      try {
        const parsedPdf = await pdfParse(a.content);
        text = (parsedPdf.text || '').trim();
      } catch (e) {
        warn(`pdf text extraction failed for ${safeName}: ${e.message}`);
      }

      extractedTexts.push({
        fileName: a.filename || safeName,
        url: urlData?.publicUrl || null,
        text: text.substring(0, 30000), // guard the prompt size
      });
    }

    // ---- Analyze via the local endpoint (same logic path as N8N used) ----
    const resp = await fetch(`http://127.0.0.1:${port}/api/timesheets/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ companyId, senderEmail, recipientEmail, extractedTexts }),
    });

    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      throw new Error(`analyze returned ${resp.status}: ${body.error || body.detail || 'unknown'}`);
    }

    // ---- Stamp message_id on the created row for dedupe ----
    const createdId = body.id || body.log?.id || (Array.isArray(body) ? body[0]?.id : null);
    if (createdId) {
      await pool.query('UPDATE automation_logs SET message_id = $1 WHERE id = $2', [messageId, createdId]);
    } else {
      // Fallback: stamp the most recent row for this sender/company
      await pool.query(
        `UPDATE automation_logs SET message_id = $1
         WHERE id = (SELECT id FROM automation_logs
                     WHERE company_id = $2 AND sender_email = $3 AND message_id IS NULL
                     ORDER BY id DESC LIMIT 1)`,
        [messageId, companyId, senderEmail]
      );
    }

    await markSeen(client, uid);
    attemptCounts.delete(messageId);
    log(`processed ${messageId} — ${pdfs.length} PDF(s), log #${createdId || '?'}`);
  } catch (err) {
    // Leave unseen → retried next cycle (bounded by MAX_ATTEMPTS)
    warn(`error on ${messageId} (attempt ${attemptCounts.get(messageId) || 1}): ${err.message}`);
  }
}

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------
async function markSeen(client, uid) {
  await client.messageFlagsAdd({ uid: String(uid) }, ['\\Seen'], { uid: false })
    .catch(e => warn(`could not mark uid ${uid} seen: ${e.message}`));
}

async function resolveCompanyId(pool) {
  if (process.env.COMPANY_ID) return parseInt(process.env.COMPANY_ID, 10);
  if (companyIdCache) return companyIdCache;

  const r = await pool.query('SELECT id FROM companies ORDER BY id LIMIT 2');
  if (r.rows.length === 1) {
    companyIdCache = r.rows[0].id;
    log(`COMPANY_ID not set — auto-detected single company #${companyIdCache}`);
    return companyIdCache;
  }
  throw new Error('COMPANY_ID env var required when multiple companies exist');
}

async function insertSkipLog(pool, { companyId, senderEmail, recipientEmail, messageId, notes }) {
  await pool.query(
    `INSERT INTO automation_logs
       (company_id, sender_email, recipient_email, message_id,
        flagged_for_review, notes, status, has_invoice)
     VALUES ($1, $2, $3, $4, true, $5, 'skipped', false)`,
    [companyId, senderEmail, recipientEmail, messageId, notes]
  );
}

module.exports = { startEmailWorker };
