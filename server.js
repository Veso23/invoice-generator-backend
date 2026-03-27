// server.js - Complete Backend API for Railway Deployment
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const morgan = require('morgan');
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

// ── SECURITY: Fail fast if critical env vars are missing ──────────────────────
if (!process.env.JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is not set. Refusing to start.');
  process.exit(1);
}


const app = express();

// Supabase client for file uploads
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ============================================
// DEFAULT PERMISSIONS FOR EACH ROLE
// ============================================
const DEFAULT_PERMISSIONS = {
  admin: {
    can_view_dashboard: true,
    can_view_contracts: true,
    can_view_consultants: true,
    can_view_clients: true,
    can_view_timesheets: true,
    can_view_invoices: true,
    can_manage_users: true,
    can_delete_timesheets: true,
    can_create_credit_note: true
  },
  operator: {
    can_view_dashboard: false,
    can_view_contracts: false,
    can_view_consultants: true,
    can_view_clients: true,
    can_view_timesheets: true,
    can_view_invoices: true,
    can_manage_users: false,
    can_delete_timesheets: false,
    can_create_credit_note: false
  }
};


app.use(compression());
// Logging — detailed in dev, minimal in production
app.use(morgan(process.env.NODE_ENV === 'production' ? 'tiny' : 'combined'));

// CORS configuration - MUST BE BEFORE OTHER MIDDLEWARE
app.use(cors({
  origin: [
    'https://invoice-generator-frontend-inky.vercel.app',
    'http://localhost:3000'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Impersonate-Company']
}));

// Handle preflight requests with same origin whitelist (not wildcard)
app.options('*', cors({
  origin: [
    'https://invoice-generator-frontend-inky.vercel.app',
    'http://localhost:3000'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Impersonate-Company']
}));

// Middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests, please try again later.' }
});
// Trust proxy for Render deployment
app.set('trust proxy', 1);
app.use('/api/', limiter);

// Stricter rate limit for login/register — prevents brute force
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // only 10 attempts per IP per 15 min
  message: { error: 'Too many login attempts. Please try again in 15 minutes.' },
  skipSuccessfulRequests: true // successful logins don't count toward the limit
});
app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);

// Database connection with Supabase
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  client_encoding: 'UTF8',
  max: 20,                  // max connections (Supabase Pro allows 60, free allows 15)
  idleTimeoutMillis: 30000, // close idle connections after 30s
  connectionTimeoutMillis: 5000 // fail fast if can't connect in 5s
});

// Set encoding on each new connection
pool.on('connect', (client) => {
  client.query('SET client_encoding = UTF8');
  if (process.env.NODE_ENV !== 'production') {
    console.log('✅ Connected to Supabase database (UTF-8)');
  }
});

pool.on('error', (err) => {
  console.error('❌ Database connection error:', err);
});

const nodemailer = require('nodemailer');
const cron = require('node-cron');

// ============================================
// EMAIL HELPERS
// ============================================

// Reusable SMTP transporter factory
const createTransporter = (s) => {
  const smtpPort = parseInt(s.smtp_port) || 587;
  return nodemailer.createTransport({
    host: s.smtp_host, port: smtpPort, secure: smtpPort === 465,
    auth: { user: s.smtp_username, pass: s.smtp_password },
    connectionTimeout: 10000, greetingTimeout: 10000, socketTimeout: 15000,
    tls: { rejectUnauthorized: false }
  });
};

const hasSMTP = (s) => s && s.smtp_host && s.smtp_username && s.smtp_password;

const getFromAddress = (s) => `"${s.smtp_from_name || s.name}" <${s.smtp_from_email || s.smtp_username}>`;

// Send confirmation when timesheet is received
const sendTimesheetConfirmation = async (senderEmail, personName, month, s) => {
  if (!hasSMTP(s)) return;
  await createTransporter(s).sendMail({
    from: getFromAddress(s), to: senderEmail,
    subject: `Timesheet received - ${month}`,
    html: `<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;background:#f9fafb;margin:0;padding:20px"><div style="max-width:560px;margin:0 auto;background:white;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08)"><div style="background:#4f46e5;padding:28px 32px"><h1 style="color:white;margin:0;font-size:20px">${s.name}</h1></div><div style="padding:32px"><p style="font-size:16px;margin:0 0 16px">Hi ${personName || 'there'},</p><p style="margin:0 0 24px;color:#475569">We have received your timesheet for <strong>${month}</strong>. It is now being reviewed and we will process your invoice shortly.</p><div style="background:#ecfdf5;border-radius:12px;padding:20px;margin-bottom:24px"><p style="margin:0;color:#059669;font-weight:700;font-size:14px">Timesheet received successfully</p><p style="margin:8px 0 0;color:#64748b;font-size:13px">Month: ${month}</p></div><p style="color:#94a3b8;font-size:13px;margin:0">If you have any questions, please contact us.</p></div><div style="background:#f8fafc;padding:16px 32px;border-top:1px solid #f1f5f9"><p style="margin:0;color:#94a3b8;font-size:12px">${s.address || ''}</p></div></div></body></html>`
  });
};

// Send reminder to consultant who hasn't submitted
const sendTimesheetReminder = async (consultantEmail, consultantName, month, deadlineDay, s) => {
  if (!hasSMTP(s)) return;
  await createTransporter(s).sendMail({
    from: getFromAddress(s), to: consultantEmail,
    subject: `Reminder: Please submit your timesheet for ${month}`,
    html: `<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;background:#f9fafb;margin:0;padding:20px"><div style="max-width:560px;margin:0 auto;background:white;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08)"><div style="background:#f59e0b;padding:28px 32px"><h1 style="color:white;margin:0;font-size:20px">${s.name}</h1></div><div style="padding:32px"><p style="font-size:16px;margin:0 0 16px">Hi ${consultantName},</p><p style="margin:0 0 24px;color:#475569">This is a friendly reminder that we have not yet received your timesheet for <strong>${month}</strong>.</p><div style="background:#fffbeb;border-radius:12px;padding:20px;margin-bottom:24px;border:1px solid #fde68a"><p style="margin:0;color:#d97706;font-weight:700;font-size:14px">Deadline: ${deadlineDay}th of this month</p><p style="margin:8px 0 0;color:#64748b;font-size:13px">Please send your timesheet PDF to ${s.timesheet_email || 'our timesheet inbox'} as soon as possible.</p></div><p style="color:#94a3b8;font-size:13px;margin:0">If you have already sent it, please ignore this message.</p></div><div style="background:#f8fafc;padding:16px 32px;border-top:1px solid #f1f5f9"><p style="margin:0;color:#94a3b8;font-size:12px">${s.address || ''}</p></div></div></body></html>`
  });
};

// ============================================
// AUDIT TRAIL HELPER
// ============================================
const logAudit = async (companyId, userId, userEmail, action, entityType, entityId, details = {}) => {
  try {
    await pool.query(
      `INSERT INTO audit_logs (company_id, user_id, user_email, action, entity_type, entity_id, details, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
      [companyId, userId, userEmail, action, entityType, entityId, JSON.stringify(details)]
    );
  } catch (err) {
    console.error('Audit log error (non-critical):', err.message);
  }
};

// Email Service

const sendInvoiceEmail = async (invoice, companySettings, recipientEmail, recipientName) => {
  if (!companySettings.smtp_host || !companySettings.smtp_username || !companySettings.smtp_password) {
    throw new Error('Email settings not configured. Please configure SMTP in Company Settings.');
  }

  const smtpPort = parseInt(companySettings.smtp_port) || 587;
  const isSecure = smtpPort === 465;

  const transporter = nodemailer.createTransport({
    host: companySettings.smtp_host,
    port: smtpPort,
    secure: isSecure,
    auth: { user: companySettings.smtp_username, pass: companySettings.smtp_password },
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 15000,
    tls: { rejectUnauthorized: false }
  });

  try { await transporter.verify(); } catch (error) {
    throw new Error('Failed to connect to email server. Please check your SMTP settings.');
  }

  // Fetch PDF as buffer for reliable attachment (works with Supabase signed URLs)
  let pdfAttachment = null;
  if (invoice.pdf_url) {
    try {
      const pdfFetch = await fetch(invoice.pdf_url);
      if (pdfFetch.ok) {
        const buffer = Buffer.from(await pdfFetch.arrayBuffer());
        pdfAttachment = {
          filename: `Invoice-${invoice.invoice_number}.pdf`,
          content: buffer,
          contentType: 'application/pdf'
        };
      }
    } catch (e) {
      console.warn('Could not fetch PDF for attachment:', e.message);
    }
  }

  // Fetch timesheet PDF attachment if available
  let timesheetAttachment = null;
  if (invoice.timesheet_file_url) {
    try {
      const tsFetch = await fetch(invoice.timesheet_file_url);
      if (tsFetch.ok) {
        const buffer = Buffer.from(await tsFetch.arrayBuffer());
        timesheetAttachment = {
          filename: `Timesheet-${invoice.invoice_number}.pdf`,
          content: buffer,
          contentType: 'application/pdf'
        };
      }
    } catch (e) {
      console.warn('Could not fetch timesheet for attachment:', e.message);
    }
  }

  const isClientInvoice = invoice.invoice_type === 'client';
  const invoiceDate = new Date(invoice.invoice_date).toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric' });
  const dueDate = invoice.due_date ? new Date(invoice.due_date).toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric' }) : null;
  const vatEnabled = invoice.vat_enabled !== false;
  const subtotal = parseFloat(invoice.subtotal || 0).toFixed(2);
  const vatAmount = vatEnabled ? parseFloat(invoice.vat_amount || 0).toFixed(2) : null;
  const total = parseFloat(invoice.total_amount || 0).toFixed(2);
  const companyName = companySettings.name || companySettings.company_name || '';
  const senderName = companySettings.representative_name || companyName;

  const emailSubject = isClientInvoice
    ? `Invoice ${invoice.invoice_number} from ${companyName}`
    : `Your Invoice ${invoice.invoice_number} – ${companyName}`;

  const emailHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${emailSubject}</title>
</head>
<body style="margin:0;padding:0;background-color:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f1f5f9;padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">

        <!-- Header -->
        <tr><td style="background:linear-gradient(135deg,#4f46e5 0%,#6366f1 100%);border-radius:16px 16px 0 0;padding:36px 40px;text-align:center;">
          <p style="margin:0 0 6px;font-size:13px;font-weight:700;color:rgba(255,255,255,0.7);text-transform:uppercase;letter-spacing:0.1em;">${companyName}</p>
          <h1 style="margin:0;font-size:28px;font-weight:900;color:white;letter-spacing:-0.5px;">Invoice ${invoice.invoice_number}</h1>
          <p style="margin:10px 0 0;font-size:14px;color:rgba(255,255,255,0.8);">${invoiceDate}</p>
        </td></tr>

        <!-- Body -->
        <tr><td style="background:white;padding:40px;">
          <p style="margin:0 0 24px;font-size:16px;color:#374151;">Dear <strong>${recipientName}</strong>,</p>
          
          <p style="margin:0 0 28px;font-size:15px;color:#6b7280;line-height:1.6;">
            ${isClientInvoice
              ? `Please find attached invoice <strong>${invoice.invoice_number}</strong> for services rendered.${dueDate ? ` Payment is due by <strong>${dueDate}</strong>.` : ''}`
              : `Please find attached your invoice <strong>${invoice.invoice_number}</strong> for the services you provided.`
            }
          </p>

          <!-- Invoice Summary Box -->
          <table width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;margin:0 0 28px;">
            <tr><td style="padding:24px;">
              <p style="margin:0 0 16px;font-size:11px;font-weight:800;color:#94a3b8;text-transform:uppercase;letter-spacing:0.1em;">Invoice Summary</p>
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="padding:8px 0;font-size:14px;color:#6b7280;border-bottom:1px solid #e2e8f0;">Invoice Number</td>
                  <td style="padding:8px 0;font-size:14px;color:#0f172a;font-weight:700;text-align:right;border-bottom:1px solid #e2e8f0;">${invoice.invoice_number}</td>
                </tr>
                <tr>
                  <td style="padding:8px 0;font-size:14px;color:#6b7280;border-bottom:1px solid #e2e8f0;">Invoice Date</td>
                  <td style="padding:8px 0;font-size:14px;color:#0f172a;font-weight:700;text-align:right;border-bottom:1px solid #e2e8f0;">${invoiceDate}</td>
                </tr>
                ${dueDate ? `<tr>
                  <td style="padding:8px 0;font-size:14px;color:#6b7280;border-bottom:1px solid #e2e8f0;">Due Date</td>
                  <td style="padding:8px 0;font-size:14px;color:#dc2626;font-weight:700;text-align:right;border-bottom:1px solid #e2e8f0;">${dueDate}</td>
                </tr>` : ''}
                <tr>
                  <td style="padding:8px 0;font-size:14px;color:#6b7280;${vatEnabled ? 'border-bottom:1px solid #e2e8f0;' : ''}">Subtotal</td>
                  <td style="padding:8px 0;font-size:14px;color:#0f172a;font-weight:700;text-align:right;${vatEnabled ? 'border-bottom:1px solid #e2e8f0;' : ''}">€${subtotal}</td>
                </tr>
                ${vatEnabled ? `<tr>
                  <td style="padding:8px 0;font-size:14px;color:#6b7280;border-bottom:1px solid #e2e8f0;">VAT (${invoice.vat_rate}%)</td>
                  <td style="padding:8px 0;font-size:14px;color:#0f172a;font-weight:700;text-align:right;border-bottom:1px solid #e2e8f0;">€${vatAmount}</td>
                </tr>` : ''}
                <tr>
                  <td style="padding:14px 0 8px;font-size:16px;font-weight:800;color:#0f172a;">Total Amount</td>
                  <td style="padding:14px 0 8px;font-size:20px;font-weight:900;color:#4f46e5;text-align:right;">€${total}</td>
                </tr>
              </table>
            </td></tr>
          </table>

          <!-- Attachment note -->
          ${pdfAttachment ? `
          <table width="100%" cellpadding="0" cellspacing="0" style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:12px;margin:0 0 28px;">
            <tr><td style="padding:16px 20px;">
              <table cellpadding="0" cellspacing="0"><tr>
                <td style="padding-right:12px;font-size:24px;">📎</td>
                <td>
                  <p style="margin:0;font-size:14px;font-weight:700;color:#1d4ed8;">Attached Documents</p>
                  <p style="margin:4px 0 0;font-size:13px;color:#3b82f6;">Invoice-${invoice.invoice_number}.pdf${timesheetAttachment ? `<br>Timesheet-${invoice.invoice_number}.pdf` : ''}</p>
                </td>
              </tr></table>
            </td></tr>
          </table>` : invoice.pdf_url ? `
          <div style="text-align:center;margin:0 0 28px;">
            <a href="${invoice.pdf_url}" style="display:inline-block;background:#4f46e5;color:white;padding:14px 32px;text-decoration:none;border-radius:10px;font-size:15px;font-weight:700;">
              📄 Download Invoice PDF
            </a>
          </div>` : ''}

          <p style="margin:0 0 8px;font-size:15px;color:#6b7280;line-height:1.6;">
            ${isClientInvoice 
              ? 'If you have any questions about this invoice, please do not hesitate to contact us.' 
              : 'Thank you for your continued work with us.'}
          </p>

          <p style="margin:24px 0 0;font-size:15px;color:#374151;">
            Kind regards,<br>
            <strong>${senderName}</strong>
            ${companySettings.company_email ? `<br><span style="color:#6b7280;font-size:13px;">${companySettings.company_email}</span>` : ''}
          </p>
        </td></tr>

        <!-- Footer -->
        <tr><td style="background:#f8fafc;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 16px 16px;padding:20px 40px;text-align:center;">
          <p style="margin:0;font-size:12px;color:#94a3b8;">${companyName}${companySettings.address ? ' · ' + companySettings.address : ''}</p>
          ${companySettings.vat ? `<p style="margin:4px 0 0;font-size:12px;color:#94a3b8;">VAT: ${companySettings.vat}</p>` : ''}
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>`;

  const info = await transporter.sendMail({
    from: `"${companySettings.smtp_from_name || companyName}" <${companySettings.smtp_from_email || companySettings.smtp_username}>`,
    to: recipientEmail,
    subject: emailSubject,
    html: emailHTML,
    attachments: [
      ...(pdfAttachment ? [pdfAttachment] : []),
      ...(timesheetAttachment ? [timesheetAttachment] : [])
    ]
  });

  return info;
};


// Authentication middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  // Support token as query param for file downloads (e.g. ?token=xxx)
  const token = (authHeader && authHeader.split(' ')[1]) || req.query.token;

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const result = await pool.query('SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL', [decoded.userId]);
    
    if (result.rows.length === 0) {
      return res.status(403).json({ error: 'Invalid token' });
    }

    req.user = result.rows[0];
    req.userId = result.rows[0].id; // ✅ Add userId for soft delete tracking
    next();
  } catch (error) {
    console.error('Auth error:', error);
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// ✅ Admin-only middleware - MUST BE OUTSIDE authenticateToken
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin' && req.user.role !== 'superadmin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// ✅ Super Admin middleware - for cross-company access
const requireSuperAdmin = (req, res, next) => {
  if (req.user.role !== 'superadmin') {
    return res.status(403).json({ error: 'Super Admin access required' });
  }
  next();
};

// Company middleware
const checkCompanyAccess = (req, res, next) => {
  // Super admin can override company_id via header OR query param (for file downloads)
  const impersonateHeader = req.headers['x-impersonate-company'];
  const impersonateQuery = req.query.companyId;
  const impersonate = impersonateHeader || (req.user.role === 'superadmin' ? impersonateQuery : null);

  if (req.user.role === 'superadmin' && impersonate) {
    req.companyId = parseInt(impersonate);
    req.isImpersonating = true;
    console.log('👁️ Super admin', req.user.email, 'viewing company:', req.companyId);
  } else {
    req.companyId = req.user.company_id;
    req.isImpersonating = false;
  }
  next();
};

// =============================================
// HELPER: Check for duplicates (scoped by company)
// =============================================
const checkDuplicates = async (pool, table, fields, excludeId = null, companyId = null) => {
  const errors = [];
  
  for (const { field, value, label } of fields) {
    if (!value || value.trim() === '') continue; // Skip empty values
    
    let query = `SELECT id FROM ${table} WHERE LOWER(${field}) = LOWER($1) AND deleted_at IS NULL`;
    const params = [value.trim()];
    let paramIndex = 2;
    
    // Scope to company if provided
    if (companyId) {
      query += ` AND company_id = $${paramIndex}`;
      params.push(companyId);
      paramIndex++;
    }
    
    // Exclude current record if updating
    if (excludeId) {
      query += ` AND id != $${paramIndex}`;
      params.push(excludeId);
    }
    
    const result = await pool.query(query, params);
    if (result.rows.length > 0) {
      errors.push(`${label} "${value}" already exists`);
    }
  }
  
  return errors;
};

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    database: 'Connected'
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({ 
    message: 'Invoice Generator API',
    version: '1.0.0',
    endpoints: {
      health: '/health',
      auth: '/api/auth/*',
      consultants: '/api/consultants',
      clients: '/api/clients',
      contracts: '/api/contracts',
      invoices: '/api/invoices',
      automation: '/api/automation-logs'
    }
  });
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, firstName, lastName, companyName } = req.body;

    if (!email || !password || !firstName || !lastName || !companyName) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if user exists (including soft-deleted)
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1 AND deleted_at IS NULL', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Start transaction
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Create company first
      const companyResult = await client.query(
        'INSERT INTO companies (name, created_at) VALUES ($1, NOW()) RETURNING id',
        [companyName]
      );
      const companyId = companyResult.rows[0].id;

      // Create user - FIRST USER IS ALWAYS ADMIN with full permissions
      const userResult = await client.query(
        `INSERT INTO users (email, password_hash, first_name, last_name, company_id, role, permissions, active, created_at) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW()) 
         RETURNING id, email, first_name, last_name, role, permissions, company_id, active`,
        [email, hashedPassword, firstName, lastName, companyId, 'admin', JSON.stringify(DEFAULT_PERMISSIONS.admin), true]
      );

      await client.query('COMMIT');

      const user = userResult.rows[0];
      const token = jwt.sign(
        { userId: user.id, companyId: user.company_id },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );

      res.status(201).json({
        message: 'User created successfully',
        token,
        user: {
          id: user.id,
          email: user.email,
          firstName: user.first_name,
          lastName: user.last_name,
          role: user.role,
          permissions: user.permissions || DEFAULT_PERMISSIONS.admin,
          companyId: user.company_id,
          active: user.active
        }
      });
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================
// LOGIN - UPDATED TO RETURN PERMISSIONS
// ============================================
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user with company name (exclude soft-deleted)
    const result = await pool.query(`
      SELECT u.*, c.name as company_name 
      FROM users u 
      LEFT JOIN companies c ON u.company_id = c.id 
      WHERE u.email = $1 AND u.deleted_at IS NULL
    `, [email]);
    const user = result.rows[0];

    if (!user || !await bcrypt.compare(password, user.password_hash)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // ✅ Check if user is active
    if (!user.active) {
      return res.status(403).json({ error: 'Account has been disabled. Contact your administrator.' });
    }

    // Update last login
    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);

    const token = jwt.sign(
      { userId: user.id, companyId: user.company_id },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // ✅ UPDATED: Return permissions and company name in login response
    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role,
        permissions: user.permissions || DEFAULT_PERMISSIONS[user.role] || DEFAULT_PERMISSIONS.operator,
        companyId: user.company_id,
        companyName: user.company_name,
        active: user.active
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================
// CONSULTANT ROUTES - WITH SOFT DELETE
// =============================================

// GET all consultants (exclude soft-deleted)
app.get('/api/consultants', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { limit, offset, search } = req.query;
    const useLimit = limit ? parseInt(limit) : null;
    const useOffset = offset ? parseInt(offset) : 0;

    let whereClause = 'WHERE company_id = $1 AND deleted_at IS NULL';
    const params = [req.companyId];

    if (search) {
      params.push(`%${search.toLowerCase()}%`);
      whereClause += ` AND (LOWER(first_name) LIKE $${params.length} OR LOWER(last_name) LIKE $${params.length} OR LOWER(email) LIKE $${params.length} OR LOWER(company_name) LIKE $${params.length} OR LOWER(company_vat) LIKE $${params.length})`;
    }

    const countResult = await pool.query(`SELECT COUNT(*) FROM consultants ${whereClause}`, params);
    const total = parseInt(countResult.rows[0].count);

    let query = `SELECT * FROM consultants ${whereClause} ORDER BY created_at DESC`;
    if (useLimit) {
      params.push(useLimit);
      query += ` LIMIT $${params.length}`;
      params.push(useOffset);
      query += ` OFFSET $${params.length}`;
    }

    const result = await pool.query(query, params);
    res.json(useLimit ? { data: result.rows, total, limit: useLimit, offset: useOffset } : result.rows);
  } catch (error) {
    console.error('Get consultants error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET deleted consultants (admin only)
app.get('/api/consultants/deleted', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.*, u.email as deleted_by_email 
       FROM consultants c 
       LEFT JOIN users u ON c.deleted_by = u.id
       WHERE c.company_id = $1 AND c.deleted_at IS NOT NULL 
       ORDER BY c.deleted_at DESC`,
      [req.companyId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get deleted consultants error:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST - Add consultant (✅ FIXED: Added checkCompanyAccess and company_id)
app.post('/api/consultants', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { 
      firstName, lastName, companyName, companyAddress, companyVat, 
      phone, email, iban, swift, consultantContractId 
    } = req.body;

    // Check for duplicates within the same company (exclude soft-deleted)
    const duplicateErrors = await checkDuplicates(pool, 'consultants', [
      { field: 'company_vat', value: companyVat, label: 'Company VAT' },
      { field: 'email', value: email, label: 'Email' },
      { field: 'iban', value: iban, label: 'IBAN' }
    ], null, req.companyId);

    if (duplicateErrors.length > 0) {
      return res.status(400).json({ 
        error: 'Duplicate values found', 
        details: duplicateErrors 
      });
    }

    // ✅ FIXED: Include company_id in INSERT
    const result = await pool.query(
      `INSERT INTO consultants (first_name, last_name, company_name, company_address, company_vat, phone, email, iban, swift, consultant_contract_id, company_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`,
      [firstName, lastName, companyName, companyAddress, companyVat, phone, email, iban, swift, consultantContractId, req.companyId]
    );
    
    res.json(result.rows[0]);
  } catch (error) {
    // Handle unique constraint violations from database
    if (error.code === '23505') { // PostgreSQL unique violation
      return res.status(400).json({ 
        error: 'Duplicate value', 
        details: [error.detail] 
      });
    }
    console.error('Error adding consultant:', error);
    res.status(500).json({ error: `Failed to add consultant: ${error.message}` });
  }
});

// POST - Batch add consultants (efficient bulk insert)
app.post('/api/consultants/batch', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { consultants } = req.body;
    
    if (!Array.isArray(consultants) || consultants.length === 0) {
      return res.status(400).json({ error: 'consultants array is required' });
    }
    
    // Limit batch size
    if (consultants.length > 1000) {
      return res.status(400).json({ error: 'Maximum 1000 records per batch' });
    }
    
    const results = { success: 0, failed: 0, errors: [] };
    
    // Process in chunks of 100 for efficiency
    const chunkSize = 100;
    for (let i = 0; i < consultants.length; i += chunkSize) {
      const chunk = consultants.slice(i, i + chunkSize);
      
      // Build multi-row INSERT
      const values = [];
      const placeholders = [];
      let paramIndex = 1;
      
      for (const c of chunk) {
        placeholders.push(`($${paramIndex}, $${paramIndex + 1}, $${paramIndex + 2}, $${paramIndex + 3}, $${paramIndex + 4}, $${paramIndex + 5}, $${paramIndex + 6}, $${paramIndex + 7}, $${paramIndex + 8}, $${paramIndex + 9}, $${paramIndex + 10})`);
        values.push(
          c.firstName || '', c.lastName || '', c.companyName || '', 
          c.companyAddress || '', c.companyVat || '', c.phone || '', 
          c.email || '', c.iban || '', c.swift || '', 
          c.consultantContractId || '', req.companyId
        );
        paramIndex += 11;
      }
      
      try {
        await pool.query(`
          INSERT INTO consultants (first_name, last_name, company_name, company_address, company_vat, phone, email, iban, swift, consultant_contract_id, company_id)
          VALUES ${placeholders.join(', ')}
          ON CONFLICT (email, company_id) DO UPDATE SET
            first_name = EXCLUDED.first_name,
            last_name = EXCLUDED.last_name,
            company_name = EXCLUDED.company_name,
            company_address = EXCLUDED.company_address,
            company_vat = EXCLUDED.company_vat,
            phone = EXCLUDED.phone,
            iban = EXCLUDED.iban,
            swift = EXCLUDED.swift,
            consultant_contract_id = EXCLUDED.consultant_contract_id,
            deleted_at = NULL,
            deleted_by = NULL,
            updated_at = NOW()
        `, values);
        results.success += chunk.length;
      } catch (error) {
        results.failed += chunk.length;
        results.errors.push(`Chunk ${Math.floor(i / chunkSize) + 1}: ${error.message}`);
      }
    }
    
    res.json(results);
  } catch (error) {
    console.error('Error batch adding consultants:', error);
    res.status(500).json({ error: `Failed to batch add consultants: ${error.message}` });
  }
});

// PUT - Update consultant (✅ FIXED: Added checkCompanyAccess and company scoping)
app.put('/api/consultants/:id', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    const { 
      firstName, lastName, companyName, companyAddress, companyVat, 
      phone, email, iban, swift, consultantContractId 
    } = req.body;

    // Verify consultant belongs to company (exclude soft-deleted)
    const checkResult = await pool.query(
      'SELECT id FROM consultants WHERE id = $1 AND company_id = $2 AND deleted_at IS NULL',
      [id, req.companyId]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Consultant not found' });
    }

    // Check for duplicates (excluding current record, scoped to company)
    const duplicateErrors = await checkDuplicates(pool, 'consultants', [
      { field: 'company_vat', value: companyVat, label: 'Company VAT' },
      { field: 'email', value: email, label: 'Email' },
      { field: 'iban', value: iban, label: 'IBAN' }
    ], id, req.companyId);

    if (duplicateErrors.length > 0) {
      return res.status(400).json({ 
        error: 'Duplicate values found', 
        details: duplicateErrors 
      });
    }

    // ✅ FIXED: Scope update to company
    const result = await pool.query(
      `UPDATE consultants 
       SET first_name = $1, last_name = $2, company_name = $3, company_address = $4, 
           company_vat = $5, phone = $6, email = $7, iban = $8, swift = $9, consultant_contract_id = $10
       WHERE id = $11 AND company_id = $12 AND deleted_at IS NULL RETURNING *`,
      [firstName, lastName, companyName, companyAddress, companyVat, phone, email, iban, swift, consultantContractId, id, req.companyId]
    );
    
    res.json(result.rows[0]);
  } catch (error) {
    if (error.code === '23505') {
      return res.status(400).json({ 
        error: 'Duplicate value', 
        details: [error.detail] 
      });
    }
    console.error('Error updating consultant:', error);
    res.status(500).json({ error: 'Failed to update consultant' });
  }
});

// DELETE consultant (SOFT DELETE)
app.delete('/api/consultants/:id', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;

    // Verify consultant belongs to company (exclude already soft-deleted)
    const checkResult = await pool.query(
      'SELECT id FROM consultants WHERE id = $1 AND company_id = $2 AND deleted_at IS NULL',
      [id, req.companyId]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Consultant not found' });
    }

    // Check if consultant has active contracts (exclude soft-deleted contracts)
    const contractCheck = await pool.query(
      'SELECT COUNT(*) as count FROM contracts WHERE consultant_id = $1 AND deleted_at IS NULL',
      [id]
    );

    if (parseInt(contractCheck.rows[0].count) > 0) {
      return res.status(400).json({ 
        error: 'Cannot delete consultant with existing contracts' 
      });
    }

    // ✅ SOFT DELETE instead of hard delete
    await pool.query(
      'UPDATE consultants SET deleted_at = NOW(), deleted_by = $1 WHERE id = $2 AND company_id = $3',
      [req.userId, id, req.companyId]
    );
    await logAudit(req.companyId, req.user.id, req.user.email, 'DELETE_CONSULTANT', 'consultant', parseInt(id), {});
    res.json({ message: 'Consultant deleted successfully' });
  } catch (error) {
    console.error('Delete consultant error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Restore deleted consultant (admin only)
app.post('/api/consultants/:id/restore', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query(
      'UPDATE consultants SET deleted_at = NULL, deleted_by = NULL WHERE id = $1 AND company_id = $2',
      [id, req.companyId]
    );
    res.json({ message: 'Consultant restored successfully' });
  } catch (error) {
    console.error('Restore consultant error:', error);
    res.status(500).json({ error: error.message });
  }
});

// =============================================
// CLIENT ROUTES - WITH SOFT DELETE
// =============================================

// GET all clients (exclude soft-deleted)
app.get('/api/clients', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { limit, offset, search } = req.query;
    const useLimit = limit ? parseInt(limit) : null;
    const useOffset = offset ? parseInt(offset) : 0;

    let whereClause = 'WHERE company_id = $1 AND deleted_at IS NULL';
    const params = [req.companyId];

    if (search) {
      params.push(`%${search.toLowerCase()}%`);
      whereClause += ` AND (LOWER(first_name) LIKE $${params.length} OR LOWER(last_name) LIKE $${params.length} OR LOWER(email) LIKE $${params.length} OR LOWER(company_name) LIKE $${params.length} OR LOWER(company_vat) LIKE $${params.length})`;
    }

    const countResult = await pool.query(`SELECT COUNT(*) FROM clients ${whereClause}`, params);
    const total = parseInt(countResult.rows[0].count);

    let query = `SELECT * FROM clients ${whereClause} ORDER BY created_at DESC`;
    if (useLimit) {
      params.push(useLimit);
      query += ` LIMIT $${params.length}`;
      params.push(useOffset);
      query += ` OFFSET $${params.length}`;
    }

    const result = await pool.query(query, params);
    res.json(useLimit ? { data: result.rows, total, limit: useLimit, offset: useOffset } : result.rows);
  } catch (error) {
    console.error('Get clients error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET deleted clients (admin only)
app.get('/api/clients/deleted', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.*, u.email as deleted_by_email 
       FROM clients c 
       LEFT JOIN users u ON c.deleted_by = u.id
       WHERE c.company_id = $1 AND c.deleted_at IS NOT NULL 
       ORDER BY c.deleted_at DESC`,
      [req.companyId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get deleted clients error:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST - Add client (✅ FIXED: Added checkCompanyAccess and company_id)
app.post('/api/clients', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { 
      firstName, lastName, companyName, companyAddress, companyVat, 
      phone, email, iban, swift, clientContractId 
    } = req.body;

    // Check for duplicates within the same company
    const duplicateErrors = await checkDuplicates(pool, 'clients', [
      { field: 'company_vat', value: companyVat, label: 'Company VAT' },
      { field: 'email', value: email, label: 'Email' },
      { field: 'iban', value: iban, label: 'IBAN' }
    ], null, req.companyId);

    if (duplicateErrors.length > 0) {
      return res.status(400).json({ 
        error: 'Duplicate values found', 
        details: duplicateErrors 
      });
    }

    // ✅ FIXED: Include company_id in INSERT
    const result = await pool.query(
      `INSERT INTO clients (first_name, last_name, company_name, company_address, company_vat, phone, email, iban, swift, client_contract_id, company_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`,
      [firstName, lastName, companyName, companyAddress, companyVat, phone, email, iban, swift, clientContractId, req.companyId]
    );
    
    res.json(result.rows[0]);
  } catch (error) {
    if (error.code === '23505') {
      return res.status(400).json({ 
        error: 'Duplicate value', 
        details: [error.detail] 
      });
    }
    console.error('Error adding client:', error);
    // Return actual error message for debugging
    res.status(500).json({ error: `Failed to add client: ${error.message}` });
  }
});

// POST - Batch add clients (efficient bulk insert)
app.post('/api/clients/batch', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { clients } = req.body;
    
    if (!Array.isArray(clients) || clients.length === 0) {
      return res.status(400).json({ error: 'clients array is required' });
    }
    
    if (clients.length > 1000) {
      return res.status(400).json({ error: 'Maximum 1000 records per batch' });
    }
    
    const results = { success: 0, failed: 0, errors: [] };
    
    // Process in chunks of 100
    const chunkSize = 100;
    for (let i = 0; i < clients.length; i += chunkSize) {
      const chunk = clients.slice(i, i + chunkSize);
      
      const values = [];
      const placeholders = [];
      let paramIndex = 1;
      
      for (const c of chunk) {
        placeholders.push(`($${paramIndex}, $${paramIndex + 1}, $${paramIndex + 2}, $${paramIndex + 3}, $${paramIndex + 4}, $${paramIndex + 5}, $${paramIndex + 6}, $${paramIndex + 7}, $${paramIndex + 8}, $${paramIndex + 9}, $${paramIndex + 10})`);
        values.push(
          c.firstName || '', c.lastName || '', c.companyName || '', 
          c.companyAddress || '', c.companyVat || '', c.phone || '', 
          c.email || '', c.iban || '', c.swift || '', 
          c.clientContractId || '', req.companyId
        );
        paramIndex += 11;
      }
      
      try {
        await pool.query(`
          INSERT INTO clients (first_name, last_name, company_name, company_address, company_vat, phone, email, iban, swift, client_contract_id, company_id)
          VALUES ${placeholders.join(', ')}
          ON CONFLICT (email, company_id) DO UPDATE SET
            first_name = EXCLUDED.first_name,
            last_name = EXCLUDED.last_name,
            company_name = EXCLUDED.company_name,
            company_address = EXCLUDED.company_address,
            company_vat = EXCLUDED.company_vat,
            phone = EXCLUDED.phone,
            iban = EXCLUDED.iban,
            swift = EXCLUDED.swift,
            client_contract_id = EXCLUDED.client_contract_id,
            deleted_at = NULL,
            deleted_by = NULL,
            updated_at = NOW()
        `, values);
        results.success += chunk.length;
      } catch (error) {
        results.failed += chunk.length;
        results.errors.push(`Chunk ${Math.floor(i / chunkSize) + 1}: ${error.message}`);
      }
    }
    
    res.json(results);
  } catch (error) {
    console.error('Error batch adding clients:', error);
    res.status(500).json({ error: `Failed to batch add clients: ${error.message}` });
  }
});

// PUT - Update client (✅ FIXED: Added checkCompanyAccess and company scoping)
app.put('/api/clients/:id', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    const { 
      firstName, lastName, companyName, companyAddress, companyVat, 
      phone, email, iban, swift, clientContractId, peppolId, countryCode
    } = req.body;

    // Verify client belongs to company (exclude soft-deleted)
    const checkResult = await pool.query(
      'SELECT id FROM clients WHERE id = $1 AND company_id = $2 AND deleted_at IS NULL',
      [id, req.companyId]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Client not found' });
    }

    // Check for duplicates (excluding current record, scoped to company)
    const duplicateErrors = await checkDuplicates(pool, 'clients', [
      { field: 'company_vat', value: companyVat, label: 'Company VAT' },
      { field: 'email', value: email, label: 'Email' },
      { field: 'iban', value: iban, label: 'IBAN' }
    ], id, req.companyId);

    if (duplicateErrors.length > 0) {
      return res.status(400).json({ 
        error: 'Duplicate values found', 
        details: duplicateErrors 
      });
    }

    // ✅ FIXED: Scope update to company
    const result = await pool.query(
      `UPDATE clients 
       SET first_name = $1, last_name = $2, company_name = $3, company_address = $4, 
           company_vat = $5, phone = $6, email = $7, iban = $8, swift = $9, 
           client_contract_id = $10, peppol_id = $11, country_code = $12
       WHERE id = $13 AND company_id = $14 AND deleted_at IS NULL RETURNING *`,
      [firstName, lastName, companyName, companyAddress, companyVat, phone, email, iban, swift, clientContractId, peppolId || null, countryCode || null, id, req.companyId]
    );
    
    res.json(result.rows[0]);
  } catch (error) {
    if (error.code === '23505') {
      return res.status(400).json({ 
        error: 'Duplicate value', 
        details: [error.detail] 
      });
    }
    console.error('Error updating client:', error);
    res.status(500).json({ error: error.message });
  }
});

// DELETE client (SOFT DELETE)
app.delete('/api/clients/:id', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;

    // Verify client belongs to company (exclude already soft-deleted)
    const checkResult = await pool.query(
      'SELECT id FROM clients WHERE id = $1 AND company_id = $2 AND deleted_at IS NULL',
      [id, req.companyId]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Client not found' });
    }

    // Check if client has active contracts (exclude soft-deleted)
    const contractCheck = await pool.query(
      'SELECT COUNT(*) as count FROM contracts WHERE client_id = $1 AND deleted_at IS NULL',
      [id]
    );

    if (parseInt(contractCheck.rows[0].count) > 0) {
      return res.status(400).json({ 
        error: 'Cannot delete client with existing contracts' 
      });
    }

    // ✅ SOFT DELETE instead of hard delete
    await pool.query(
      'UPDATE clients SET deleted_at = NOW(), deleted_by = $1 WHERE id = $2 AND company_id = $3',
      [req.userId, id, req.companyId]
    );
    await logAudit(req.companyId, req.user.id, req.user.email, 'DELETE_CLIENT', 'client', parseInt(id), {});
    res.json({ message: 'Client deleted successfully' });
  } catch (error) {
    console.error('Delete client error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Restore deleted client (admin only)
app.post('/api/clients/:id/restore', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query(
      'UPDATE clients SET deleted_at = NULL, deleted_by = NULL WHERE id = $1 AND company_id = $2',
      [id, req.companyId]
    );
    res.json({ message: 'Client restored successfully' });
  } catch (error) {
    console.error('Restore client error:', error);
    res.status(500).json({ error: error.message });
  }
});

// =============================================
// BULK UPLOAD - FIXED WITH company_id
// =============================================
app.post('/api/consultants/bulk', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { consultants } = req.body;
    const results = { success: [], errors: [] };
    
    for (const consultant of consultants) {
      // Check for duplicates (scoped to company)
      const duplicateErrors = await checkDuplicates(pool, 'consultants', [
        { field: 'company_vat', value: consultant.companyVat, label: 'Company VAT' },
        { field: 'email', value: consultant.email, label: 'Email' },
        { field: 'iban', value: consultant.iban, label: 'IBAN' }
      ], null, req.companyId);

      if (duplicateErrors.length > 0) {
        results.errors.push({
          consultant: `${consultant.firstName} ${consultant.lastName}`,
          errors: duplicateErrors
        });
        continue; // Skip this record
      }

      // Insert the consultant with company_id
      try {
        const result = await pool.query(
          `INSERT INTO consultants (first_name, last_name, company_name, company_address, company_vat, phone, email, iban, swift, consultant_contract_id, company_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`,
          [consultant.firstName, consultant.lastName, consultant.companyName, consultant.companyAddress, 
           consultant.companyVat, consultant.phone, consultant.email, consultant.iban, consultant.swift, 
           consultant.consultantContractId, req.companyId]
        );
        results.success.push(result.rows[0]);
      } catch (dbError) {
        results.errors.push({
          consultant: `${consultant.firstName} ${consultant.lastName}`,
          errors: [dbError.message]
        });
      }
    }
    
    res.json({
      message: `Imported ${results.success.length} consultants, ${results.errors.length} failed`,
      success: results.success,
      errors: results.errors
    });
  } catch (error) {
    console.error('Bulk upload error:', error);
    res.status(500).json({ error: 'Bulk upload failed' });
  }
});


// Contract Routes (exclude soft-deleted)
app.get('/api/contracts', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { limit, offset, search } = req.query;
    const useLimit = limit ? parseInt(limit) : null;
    const useOffset = offset ? parseInt(offset) : 0;

    const params = [req.companyId];
    let extraWhere = '';

    if (search) {
      params.push(`%${search.toLowerCase()}%`);
      extraWhere = ` AND (LOWER(c.contract_number) LIKE $${params.length} OR LOWER(cons.first_name) LIKE $${params.length} OR LOWER(cons.last_name) LIKE $${params.length} OR LOWER(cli.company_name) LIKE $${params.length})`;
    }

    const countResult = await pool.query(
      `SELECT COUNT(*) FROM contracts c JOIN consultants cons ON c.consultant_id = cons.id JOIN clients cli ON c.client_id = cli.id WHERE c.company_id = $1 AND c.deleted_at IS NULL${extraWhere}`,
      params
    );
    const total = parseInt(countResult.rows[0].count);

    let query = `
      SELECT 
        c.id, c.uuid, c.consultant_id, c.client_id, c.contract_number,
        c.from_date, c.to_date, c.purchase_price, c.sell_price, c.currency,
        c.status, c.notes, c.vat_enabled, c.vat_rate, c.consultant_vat_enabled,
        c.consultant_vat_rate, c.company_id, c.created_at, c.updated_at,
        cons.consultant_contract_id, cli.client_contract_id,
        cons.company_name as consultant_company_name,
        cons.first_name as consultant_first_name,
        cons.last_name as consultant_last_name,
        cons.company_vat as consultant_company_vat,
        cli.company_name as client_company_name,
        cli.first_name as client_first_name,
        cli.last_name as client_last_name,
        cli.company_vat as client_company_vat
      FROM contracts c
      JOIN consultants cons ON c.consultant_id = cons.id
      JOIN clients cli ON c.client_id = cli.id
      WHERE c.company_id = $1 AND c.deleted_at IS NULL${extraWhere}
      ORDER BY c.created_at DESC`;

    if (useLimit) {
      params.push(useLimit);
      query += ` LIMIT $${params.length}`;
      params.push(useOffset);
      query += ` OFFSET $${params.length}`;
    }

    const result = await pool.query(query, params);
    res.json(useLimit ? { data: result.rows, total, limit: useLimit, offset: useOffset } : result.rows);
  } catch (error) {
    console.error('Get contracts error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET deleted contracts (admin only)
app.get('/api/contracts/deleted', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.*, u.email as deleted_by_email,
              cons.first_name as consultant_first_name, cons.last_name as consultant_last_name,
              cli.company_name as client_company_name
       FROM contracts c 
       LEFT JOIN users u ON c.deleted_by = u.id
       LEFT JOIN consultants cons ON c.consultant_id = cons.id
       LEFT JOIN clients cli ON c.client_id = cli.id
       WHERE c.company_id = $1 AND c.deleted_at IS NOT NULL 
       ORDER BY c.deleted_at DESC`,
      [req.companyId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get deleted contracts error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Timesheets Routes (exclude soft-deleted consultants)
app.get('/api/timesheets', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT al.*,
             c.first_name as consultant_first_name,
             c.last_name as consultant_last_name,
             c.company_name as consultant_company_name,
             c.id as consultant_id,
             CASE WHEN c.id IS NOT NULL THEN true ELSE false END as consultant_matched,
             CASE WHEN cr.id IS NOT NULL THEN true ELSE false END as previously_credited,
             cr.invoice_number as credited_invoice_number,
             cr.invoice_type as credited_invoice_type,
             -- check if valid (non-credited) invoices still exist per type
             CASE WHEN cons_inv.id IS NOT NULL THEN true ELSE false END as has_consultant_invoice,
             CASE WHEN cli_inv.id IS NOT NULL THEN true ELSE false END as has_client_invoice
      FROM automation_logs al
      LEFT JOIN consultants c ON al.sender_email = c.email AND c.company_id = $1 AND c.deleted_at IS NULL
      LEFT JOIN invoices cr ON cr.timesheet_id = al.id AND cr.invoice_type_detail = 'credited' AND cr.company_id = $1
      LEFT JOIN invoices cons_inv ON cons_inv.timesheet_id = al.id AND cons_inv.invoice_type = 'consultant' AND cons_inv.company_id = $1 AND cons_inv.invoice_type_detail != 'credit_note' AND cons_inv.status != 'credited'
      LEFT JOIN invoices cli_inv ON cli_inv.timesheet_id = al.id AND cli_inv.invoice_type = 'client' AND cli_inv.company_id = $1 AND cli_inv.invoice_type_detail != 'credit_note' AND cli_inv.status != 'credited'
      WHERE al.processed = false AND al.company_id = $1
      ORDER BY al.created_at DESC
    `, [req.companyId]);

    res.json(result.rows);
  } catch (error) {
    console.error('Get timesheets error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.post('/api/contracts', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const {
      contractNumber,
      consultantId, clientId, fromDate, toDate,
      purchasePrice, sellPrice,
      vatEnabled = false,
      vatRate,
      consultantVatEnabled = false,
      consultantVatRate
    } = req.body;

    if (!contractNumber || !consultantId || !clientId || !fromDate || !toDate || !purchasePrice || !sellPrice) {
      return res.status(400).json({ error: 'All fields including contract number are required' });
    }

    // ✅ SANITIZE: Convert empty strings to null for numeric fields
    const sanitizedVatRate = vatRate === '' || vatRate === undefined ? null : parseFloat(vatRate);
    const sanitizedConsultantVatRate = consultantVatRate === '' || consultantVatRate === undefined ? null : parseFloat(consultantVatRate);

    const timestamp = Date.now();
    const consultantContractId = `CONS-${timestamp}`;
    const clientContractId = `CLI-${timestamp}`;

    const result = await pool.query(`
      INSERT INTO contracts 
      (contract_number, consultant_id, client_id, from_date, to_date, purchase_price, sell_price, 
       consultant_contract_id, client_contract_id, vat_enabled, vat_rate, 
       consultant_vat_enabled, consultant_vat_rate, company_id, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW()) 
      RETURNING *
    `, [
      contractNumber, consultantId, clientId, fromDate, toDate, 
      purchasePrice, sellPrice, 
      consultantContractId, clientContractId,
      vatEnabled, sanitizedVatRate,
      consultantVatEnabled, sanitizedConsultantVatRate,
      req.companyId
    ]);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Create contract error:', error);
    
    if (error.code === '23505' && error.constraint === 'contracts_contract_number_key') {
      res.status(400).json({ error: 'Contract number already exists. Please use a different number.' });
    } else {
      res.status(500).json({ error: error.message });
    }
  }
});

// POST - Batch add contracts (efficient bulk insert)
app.post('/api/contracts/batch', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const { contracts } = req.body;
    
    if (!Array.isArray(contracts) || contracts.length === 0) {
      return res.status(400).json({ error: 'contracts array is required' });
    }
    
    if (contracts.length > 500) {
      return res.status(400).json({ error: 'Maximum 500 contracts per batch' });
    }
    
    const results = { success: 0, failed: 0, errors: [] };
    
    // Process in chunks of 50 (contracts have more fields)
    const chunkSize = 50;
    for (let i = 0; i < contracts.length; i += chunkSize) {
      const chunk = contracts.slice(i, i + chunkSize);
      
      const values = [];
      const placeholders = [];
      let paramIndex = 1;
      
      for (const c of chunk) {
        const timestamp = Date.now() + Math.random() * 1000; // Unique per row
        const consultantContractId = `CONS-${Math.floor(timestamp)}`;
        const clientContractId = `CLI-${Math.floor(timestamp)}`;
        
        placeholders.push(`($${paramIndex}, $${paramIndex + 1}, $${paramIndex + 2}, $${paramIndex + 3}, $${paramIndex + 4}, $${paramIndex + 5}, $${paramIndex + 6}, $${paramIndex + 7}, $${paramIndex + 8}, $${paramIndex + 9}, $${paramIndex + 10}, $${paramIndex + 11}, $${paramIndex + 12}, $${paramIndex + 13})`);
        values.push(
          c.contractNumber, c.consultantId, c.clientId,
          c.fromDate, c.toDate,
          parseFloat(c.purchasePrice) || 0, parseFloat(c.sellPrice) || 0,
          c.vatEnabled === true || c.vatEnabled === 'true',
          parseFloat(c.vatRate) || null,
          c.consultantVatEnabled === true || c.consultantVatEnabled === 'true',
          parseFloat(c.consultantVatRate) || null,
          consultantContractId,
          clientContractId,
          req.companyId
        );
        paramIndex += 14;
      }
      
      try {
        const result = await pool.query(`
          INSERT INTO contracts (contract_number, consultant_id, client_id, from_date, to_date, purchase_price, sell_price, vat_enabled, vat_rate, consultant_vat_enabled, consultant_vat_rate, consultant_contract_id, client_contract_id, company_id)
          VALUES ${placeholders.join(', ')}
          ON CONFLICT (contract_number, company_id) DO UPDATE SET
            consultant_id = EXCLUDED.consultant_id,
            client_id = EXCLUDED.client_id,
            from_date = EXCLUDED.from_date,
            to_date = EXCLUDED.to_date,
            purchase_price = EXCLUDED.purchase_price,
            sell_price = EXCLUDED.sell_price,
            vat_enabled = EXCLUDED.vat_enabled,
            vat_rate = EXCLUDED.vat_rate,
            consultant_vat_enabled = EXCLUDED.consultant_vat_enabled,
            consultant_vat_rate = EXCLUDED.consultant_vat_rate,
            deleted_at = NULL,
            deleted_by = NULL,
            updated_at = NOW()
          RETURNING id
        `, values);
        results.success += result.rowCount;
      } catch (error) {
        results.failed += chunk.length;
        results.errors.push(`Chunk ${Math.floor(i / chunkSize) + 1}: ${error.message}`);
      }
    }
    
    res.json(results);
  } catch (error) {
    console.error('Error batch adding contracts:', error);
    res.status(500).json({ error: `Failed to batch add contracts: ${error.message}` });
  }
});

// Update contract (Admin only)
app.put('/api/contracts/:id', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      contractNumber, consultantId, clientId, fromDate, toDate,
      purchasePrice, sellPrice, vatEnabled = false, vatRate,
      consultantVatEnabled = false, consultantVatRate
    } = req.body;

    // Verify contract belongs to company (exclude soft-deleted)
    const checkResult = await pool.query(
      'SELECT id FROM contracts WHERE id = $1 AND company_id = $2 AND deleted_at IS NULL',
      [id, req.companyId]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Contract not found' });
    }

    // Sanitize VAT rates
    const sanitizedVatRate = vatRate === '' || vatRate === undefined ? null : parseFloat(vatRate);
    const sanitizedConsultantVatRate = consultantVatRate === '' || consultantVatRate === undefined ? null : parseFloat(consultantVatRate);

    const result = await pool.query(
      `UPDATE contracts 
       SET contract_number = $1, consultant_id = $2, client_id = $3, from_date = $4, to_date = $5,
           purchase_price = $6, sell_price = $7, vat_enabled = $8, vat_rate = $9,
           consultant_vat_enabled = $10, consultant_vat_rate = $11, updated_at = NOW()
       WHERE id = $12 AND company_id = $13 AND deleted_at IS NULL
       RETURNING *`,
      [contractNumber, consultantId, clientId, fromDate, toDate, purchasePrice, sellPrice,
       vatEnabled, sanitizedVatRate, consultantVatEnabled, sanitizedConsultantVatRate, id, req.companyId]
    );

    res.json({ message: 'Contract updated successfully', contract: result.rows[0] });
  } catch (error) {
    console.error('Update contract error:', error);
    if (error.code === '23505') {
      res.status(400).json({ error: 'Contract number already exists' });
    } else {
      res.status(500).json({ error: error.message });
    }
  }
});

// Delete contract (Admin only) - SOFT DELETE
app.delete('/api/contracts/:id', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;

    // Check if contract has invoices
    const invoiceCheck = await pool.query(
      'SELECT COUNT(*) as count FROM invoices WHERE contract_id = $1',
      [id]
    );

    if (parseInt(invoiceCheck.rows[0].count) > 0) {
      return res.status(400).json({ 
        error: 'Cannot delete contract with existing invoices. Delete invoices first.' 
      });
    }

    // Verify contract belongs to company (exclude already soft-deleted)
    const checkResult = await pool.query(
      'SELECT id FROM contracts WHERE id = $1 AND company_id = $2 AND deleted_at IS NULL',
      [id, req.companyId]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Contract not found' });
    }

    // ✅ SOFT DELETE instead of hard delete
    await pool.query(
      'UPDATE contracts SET deleted_at = NOW(), deleted_by = $1 WHERE id = $2',
      [req.userId, id]
    );
    await logAudit(req.companyId, req.user.id, req.user.email, 'DELETE_CONTRACT', 'contract', parseInt(id), {});
    res.json({ message: 'Contract deleted successfully' });
  } catch (error) {
    console.error('Delete contract error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Restore deleted contract (admin only)
app.post('/api/contracts/:id/restore', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query(
      'UPDATE contracts SET deleted_at = NULL, deleted_by = NULL WHERE id = $1 AND company_id = $2',
      [id, req.companyId]
    );
    res.json({ message: 'Contract restored successfully' });
  } catch (error) {
    console.error('Restore contract error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Match timesheet to consultant
app.put('/api/timesheets/:id/match', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    const { consultantId } = req.body;

    if (!consultantId) {
      return res.status(400).json({ error: 'Consultant ID is required' });
    }

    // Verify consultant belongs to the same company (exclude soft-deleted)
    const consultant = await pool.query(
      'SELECT * FROM consultants WHERE id = $1 AND company_id = $2 AND deleted_at IS NULL',
      [consultantId, req.companyId]
    );

    if (consultant.rows.length === 0) {
      return res.status(404).json({ error: 'Consultant not found' });
    }

    // Update automation_logs with consultant email to create the match
    const result = await pool.query(
      'UPDATE automation_logs SET sender_email = $1 WHERE id = $2 RETURNING *',
      [consultant.rows[0].email, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Timesheet not found' });
    }

    res.json({ success: true, message: 'Timesheet matched successfully' });
  } catch (error) {
    console.error('Match timesheet error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get available contracts for a timesheet
app.get('/api/timesheets/:id/available-contracts', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Get timesheet
    const timesheetResult = await pool.query(
      'SELECT * FROM automation_logs WHERE id = $1',
      [id]
    );
    
    if (timesheetResult.rows.length === 0) {
      return res.status(404).json({ error: 'Timesheet not found' });
    }
    
    const timesheet = timesheetResult.rows[0];
    
    if (!timesheet.sender_email) {
      return res.status(400).json({ error: 'Timesheet must be matched to a consultant first' });
    }
    
    if (!timesheet.month) {
      return res.status(400).json({ error: 'Timesheet month must be set first' });
    }
    
    // Find consultant (exclude soft-deleted)
    const normalizedEmail = timesheet.sender_email.trim().toLowerCase();
    const consultantResult = await pool.query(
      `SELECT * FROM consultants WHERE LOWER(TRIM(email)) = $1 AND company_id = $2 AND deleted_at IS NULL`,
      [normalizedEmail, req.companyId]
    );
    
    if (consultantResult.rows.length === 0) {
      return res.status(404).json({ error: 'Consultant not found' });
    }
    
    const consultant = consultantResult.rows[0];
    
    // Calculate period dates
    const monthName = timesheet.month;
    const monthNames = ['January', 'February', 'March', 'April', 'May', 'June', 
                        'July', 'August', 'September', 'October', 'November', 'December'];
    const timesheetMonthIndex = monthNames.findIndex(m => m.toLowerCase() === monthName.toLowerCase());
    
    if (timesheetMonthIndex === -1) {
      return res.status(400).json({ error: `Invalid month: ${monthName}` });
    }
    
    const now = new Date();
    const currentMonth = now.getMonth();
    const currentYear = now.getFullYear();
    
    let year;
    if (timesheetMonthIndex > currentMonth + 1) {
      year = currentYear - 1;
    } else {
      year = currentYear;
    }
    
    const periodFrom = new Date(year, timesheetMonthIndex, 1);
    const periodTo = new Date(year, timesheetMonthIndex + 1, 0);
    const periodFromStr = periodFrom.toISOString().split('T')[0];
    const periodToStr = periodTo.toISOString().split('T')[0];
    
    // Find ALL contracts that overlap with the timesheet period (exclude soft-deleted)
    const contractsResult = await pool.query(
      `SELECT c.*, 
              cli.first_name as client_first_name, 
              cli.last_name as client_last_name,
              cli.company_name as client_company_name,
              CASE 
                WHEN c.to_date < CURRENT_DATE THEN 'ended'
                WHEN c.from_date > CURRENT_DATE THEN 'future'
                ELSE 'active'
              END as status
       FROM contracts c
       JOIN clients cli ON c.client_id = cli.id
       WHERE c.consultant_id = $1 
       AND c.company_id = $2 
       AND c.from_date <= $3
       AND c.to_date >= $4
       AND c.deleted_at IS NULL
       ORDER BY c.from_date DESC`,
      [consultant.id, req.companyId, periodToStr, periodFromStr]
    );
    
    res.json({
      contracts: contractsResult.rows,
      consultant: {
        id: consultant.id,
        name: `${consultant.first_name} ${consultant.last_name}`
      },
      period: {
        month: monthName,
        year: year,
        from: periodFromStr,
        to: periodToStr
      },
      currentContractId: timesheet.contract_id,
      requiresSelection: contractsResult.rows.length > 1
    });
  } catch (error) {
    console.error('Get available contracts error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Set contract for a timesheet
app.put('/api/timesheets/:id/contract', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    const { contractId } = req.body;
    
    if (!contractId) {
      return res.status(400).json({ error: 'Contract ID is required' });
    }
    
    // Verify contract belongs to the same company (exclude soft-deleted)
    const contract = await pool.query(
      'SELECT * FROM contracts WHERE id = $1 AND company_id = $2 AND deleted_at IS NULL',
      [contractId, req.companyId]
    );
    
    if (contract.rows.length === 0) {
      return res.status(404).json({ error: 'Contract not found' });
    }
    
    // Update timesheet with contract_id
    const result = await pool.query(
      'UPDATE automation_logs SET contract_id = $1 WHERE id = $2 RETURNING *',
      [contractId, id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Timesheet not found' });
    }
    
    console.log(`✅ Contract ${contractId} set for timesheet ${id}`);
    res.json({ 
      success: true, 
      message: 'Contract set successfully',
      timesheet: result.rows[0],
      contract: contract.rows[0]
    });
  } catch (error) {
    console.error('Set contract error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update timesheet days
app.put('/api/timesheets/:id/days', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    const { days } = req.body;

    if (days === undefined || days === null || isNaN(days) || days < 0) {
      return res.status(400).json({ error: 'Valid days value is required' });
    }

    // Verify timesheet belongs to user's company
    const checkResult = await pool.query(
      `SELECT al.* FROM automation_logs al
       LEFT JOIN consultants c ON LOWER(TRIM(al.sender_email)) = LOWER(TRIM(c.email)) AND c.deleted_at IS NULL
       WHERE al.id = $1 AND (al.company_id = $2 OR c.company_id = $2)`,
      [id, req.companyId]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Timesheet not found' });
    }

    const result = await pool.query(
      'UPDATE automation_logs SET pdf_days = $1 WHERE id = $2 RETURNING *',
      [days, id]
    );

    console.log('✅ Days updated for timesheet:', id, 'to:', days);
    res.json({ success: true, message: 'Days updated successfully', timesheet: result.rows[0] });
  } catch (error) {
    console.error('Update timesheet days error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update timesheet month
app.put('/api/timesheets/:id/month', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    const { month } = req.body;
    
    // Validate month
    const validMonths = ['January', 'February', 'March', 'April', 'May', 'June', 
                        'July', 'August', 'September', 'October', 'November', 'December'];
    
    if (!validMonths.includes(month)) {
      return res.status(400).json({ error: 'Invalid month' });
    }
    
    // Verify timesheet belongs to user's company
    const checkResult = await pool.query(
      `SELECT al.* FROM automation_logs al
       LEFT JOIN consultants c ON LOWER(TRIM(al.sender_email)) = LOWER(TRIM(c.email)) AND c.deleted_at IS NULL
       WHERE al.id = $1 AND (al.company_id = $2 OR c.company_id = $2)`,
      [id, req.companyId]
    );
    
    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Timesheet not found' });
    }
    
    const result = await pool.query(
      `UPDATE automation_logs 
       SET month = $1 
       WHERE id = $2
       RETURNING *`,
      [month, id]
    );
    
    console.log('✅ Month updated for timesheet:', id, 'to:', month);
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Update month error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Flag/unflag timesheet for review
app.put('/api/timesheets/:id/flag-review', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    const { flagged } = req.body;
    
    // Verify timesheet belongs to user's company
    const checkResult = await pool.query(
      `SELECT al.* FROM automation_logs al
       LEFT JOIN consultants c ON LOWER(TRIM(al.sender_email)) = LOWER(TRIM(c.email)) AND c.deleted_at IS NULL
       WHERE al.id = $1 AND (al.company_id = $2 OR c.company_id = $2)`,
      [id, req.companyId]
    );
    
    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Timesheet not found' });
    }
    
    const result = await pool.query(
      `UPDATE automation_logs 
       SET flagged_for_review = $1 
       WHERE id = $2
       RETURNING *`,
      [flagged === true, id]
    );
    
    console.log(`${flagged ? '🚩 Flagged' : '✅ Unflagged'} timesheet:`, id);
    await logAudit(req.companyId, req.user.id, req.user.email,
      flagged ? 'FLAG_FOR_REVIEW' : 'UNFLAG_REVIEW', 'timesheet', parseInt(id),
      { flagged, sender_email: result.rows[0].sender_email, month: result.rows[0].month });

    res.json({ 
      message: `Timesheet ${flagged ? 'flagged for review' : 'unflagged'}`,
      timesheet: result.rows[0]
    });
  } catch (error) {
    console.error('Flag review error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Invoice Generation
app.post('/api/invoices/generate/:contractId', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { contractId } = req.params;

    // Get contract with consultant and client details (exclude soft-deleted)
const contractResult = await pool.query(`
  SELECT c.*, 
         cons.first_name as consultant_first_name, cons.last_name as consultant_last_name,
         cons.company_name as consultant_company, cons.company_address as consultant_address,
         cons.company_vat as consultant_vat, cons.iban as consultant_iban, cons.swift as consultant_swift,
         cli.first_name as client_first_name, cli.last_name as client_last_name,
         cli.company_name as client_company, cli.company_address as client_address,
         cli.company_vat as client_vat, cli.iban as client_iban, cli.swift as client_swift,
         comp.name as company_name, comp.address as company_address, comp.vat as company_vat,
         comp.default_vat_rate
  FROM contracts c
  JOIN consultants cons ON c.consultant_id = cons.id
  JOIN clients cli ON c.client_id = cli.id
  JOIN companies comp ON c.company_id = comp.id
  WHERE c.id = $1 AND c.company_id = $2 AND c.deleted_at IS NULL
`, [contractId, req.companyId]);

    if (contractResult.rows.length === 0) {
      return res.status(404).json({ error: 'Contract not found' });
    }

    const contract = contractResult.rows[0];
    
    // Calculate days
    const fromDate = new Date(contract.from_date);
    const toDate = new Date(contract.to_date);
    const days = Math.ceil((toDate - fromDate) / (1000 * 60 * 60 * 24)) + 1;
    const year = new Date().getFullYear();

    // ✅ Generate invoice numbers with SEPARATE sequences
    // Get consultant full name for invoice numbering (remove spaces and special chars)
    const consultantFullName = (contract.consultant_first_name + contract.consultant_last_name)
      .replace(/[^a-zA-Z0-9]/g, '');
    
    // Count CLIENT invoices only (one sequence for all client invoices)
    const clientInvoiceCountResult = await pool.query(
      `SELECT COUNT(*) FROM invoices WHERE company_id = $1 AND invoice_type = 'client'`,
      [req.companyId]
    );
    const clientInvoiceCount = parseInt(clientInvoiceCountResult.rows[0].count);
    const clientInvoiceNumber = `INV-${year}-${String(clientInvoiceCount + 1).padStart(4, '0')}`;
    
    // Count CONSULTANT invoices for THIS consultant only (separate sequence per consultant)
    const consultantInvoiceCountResult = await pool.query(
      `SELECT COUNT(*) FROM invoices i
       JOIN contracts c ON i.contract_id = c.id
       WHERE i.company_id = $1 AND i.invoice_type = 'consultant' AND c.consultant_id = $2`,
      [req.companyId, contract.consultant_id]
    );
    const consultantInvoiceCount = parseInt(consultantInvoiceCountResult.rows[0].count);
    const consultantInvoiceNumber = `INV-${year}-${String(consultantInvoiceCount + 1).padStart(4, '0')}-${consultantFullName}`;

// Calculate amounts using company's default VAT rate
const vatRate = contract.default_vat_rate || 21.00;
const vatDecimal = vatRate / 100;

const consultantSubtotal = Math.round(contract.purchase_price * days * 100) / 100;
const consultantVAT = Math.round(consultantSubtotal * vatDecimal * 100) / 100;
const consultantTotal = Math.round((consultantSubtotal + consultantVAT) * 100) / 100;

const clientSubtotal = Math.round(contract.sell_price * days * 100) / 100;
const clientVAT = Math.round(clientSubtotal * vatDecimal * 100) / 100;
const clientTotal = Math.round((clientSubtotal + clientVAT) * 100) / 100;

// Create consultant invoice
const consultantInvoiceResult = await pool.query(`
  INSERT INTO invoices 
  (invoice_number, contract_id, invoice_type, invoice_date, period_from, period_to,
   days_worked, daily_rate, subtotal, vat_rate, vat_amount, total_amount, company_id, created_by, created_at)
  VALUES ($1, $2, 'consultant', CURRENT_DATE, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
  RETURNING *
`, [consultantInvoiceNumber, contractId, contract.from_date, contract.to_date,
    days, contract.purchase_price, consultantSubtotal, vatRate, consultantVAT, consultantTotal, req.companyId, req.user.id]);

// Create client invoice
const clientInvoiceResult = await pool.query(`
  INSERT INTO invoices 
  (invoice_number, contract_id, invoice_type, invoice_date, period_from, period_to,
   days_worked, daily_rate, subtotal, vat_rate, vat_amount, total_amount, company_id, created_by, created_at)
  VALUES ($1, $2, 'client', CURRENT_DATE, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
  RETURNING *
`, [clientInvoiceNumber, contractId, contract.from_date, contract.to_date,
    days, contract.sell_price, clientSubtotal, vatRate, clientVAT, clientTotal, req.companyId, req.user.id]);

    res.json({
      consultantInvoice: consultantInvoiceResult.rows[0],
      clientInvoice: clientInvoiceResult.rows[0],
      contract,
      days
    });

  } catch (error) {
    console.error('Generate invoices error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Generate invoice from timesheet using approved days
app.post('/api/timesheets/:id/generate-invoice', authenticateToken, checkCompanyAccess, async (req, res) => {
  const client = await pool.connect();
  
  try {
    const { id } = req.params;
    
    // Start transaction
    await client.query('BEGIN');
    
    // Get timesheet
    const timesheetResult = await client.query(
      'SELECT * FROM automation_logs WHERE id = $1',
      [id]
    );
    
    if (timesheetResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Timesheet not found' });
    }
    
    const timesheet = timesheetResult.rows[0];
    
    // Calculate days - use days if available, otherwise convert hours to days
    const days = parseFloat(timesheet.pdf_days) || parseFloat(timesheet.email_days) || 0;
    const hours = parseFloat(timesheet.pdf_hours) || parseFloat(timesheet.email_hours) || 0;
    
    let daysWorked;
    if (days > 0) {
      daysWorked = parseFloat(days.toFixed(2));
    } else if (hours > 0) {
      daysWorked = parseFloat((hours / 8).toFixed(2));
    } else {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'No days or hours found in timesheet' });
    }
    
    // Must have month set
    if (!timesheet.month) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Timesheet month is not set. Please set the month first.' });
    }
    
    // Must be matched to consultant
    if (!timesheet.sender_email) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Please match timesheet to consultant first' });
    }
    
    // Normalize email
    const normalizedEmail = timesheet.sender_email.trim().toLowerCase();
    
    // Find consultant (exclude soft-deleted)
    const consultantResult = await client.query(
      `SELECT * FROM consultants 
       WHERE LOWER(TRIM(email)) = $1 
       AND company_id = $2
       AND deleted_at IS NULL`,
      [normalizedEmail, req.companyId]
    );
    
    if (consultantResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ 
        error: `Consultant not found with email: ${normalizedEmail} in company ${req.companyId}`
      });
    }
    
    const consultant = consultantResult.rows[0];
    
    // ✅ Calculate the correct year for the timesheet
    const monthName = timesheet.month;
    const monthNames = ['January', 'February', 'March', 'April', 'May', 'June', 
                        'July', 'August', 'September', 'October', 'November', 'December'];
    const timesheetMonthIndex = monthNames.findIndex(m => m.toLowerCase() === monthName.toLowerCase());
    
    if (timesheetMonthIndex === -1) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `Invalid month: ${monthName}` });
    }
    
    const now = new Date();
    const currentMonth = now.getMonth(); // 0-11
    const currentYear = now.getFullYear();
    
    // Determine the correct year for the timesheet
    let year;
    if (timesheetMonthIndex > currentMonth + 1) {
      year = currentYear - 1;
    } else {
      year = currentYear;
    }
    
    console.log(`Timesheet month: ${monthName}, Current month: ${currentMonth}, Calculated year: ${year}`);
    
    // Calculate the timesheet period dates
    const periodFrom = new Date(year, timesheetMonthIndex, 1);
    const periodTo = new Date(year, timesheetMonthIndex + 1, 0); // Last day of month
    
    // Format dates for SQL query (YYYY-MM-DD)
    const periodFromStr = periodFrom.toISOString().split('T')[0];
    const periodToStr = periodTo.toISOString().split('T')[0];
    
    console.log(`Looking for contract covering period: ${periodFromStr} to ${periodToStr}`);
    
    let contract;
    
    // ✅ Re-invoice: if timesheet has a credited invoice, use its contract_id directly
    const creditedInvoiceResult = await client.query(
      `SELECT contract_id FROM invoices 
       WHERE timesheet_id = $1 AND company_id = $2 AND status = 'credited' 
       ORDER BY id DESC LIMIT 1`,
      [id, req.companyId]
    );

    if (creditedInvoiceResult.rows.length > 0) {
      const creditedContractId = creditedInvoiceResult.rows[0].contract_id;
      const creditedContractResult = await client.query(
        `SELECT * FROM contracts WHERE id = $1 AND company_id = $2`,
        [creditedContractId, req.companyId]
      );
      if (creditedContractResult.rows.length > 0) {
        contract = creditedContractResult.rows[0];
        console.log(`Re-invoice: using contract from credited invoice: ${contract.contract_number}`);
      }
    }

    // ✅ Check if contract is already selected on timesheet
    if (!contract && timesheet.contract_id) {
      console.log(`Using pre-selected contract: ${timesheet.contract_id}`);
      const selectedContractResult = await client.query(
        `SELECT * FROM contracts WHERE id = $1 AND company_id = $2 AND deleted_at IS NULL`,
        [timesheet.contract_id, req.companyId]
      );
      
      if (selectedContractResult.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Selected contract not found' });
      }
      
      contract = selectedContractResult.rows[0];
    } else if (!contract) {
      // ✅ Find ALL contracts that overlap with this period (exclude soft-deleted)
      const contractsResult = await client.query(
        `SELECT c.*, 
                cli.company_name as client_company_name
         FROM contracts c
         JOIN clients cli ON c.client_id = cli.id
         WHERE c.consultant_id = $1 
         AND c.company_id = $2 
         AND c.from_date <= $3
         AND c.to_date >= $4
         AND c.deleted_at IS NULL
         ORDER BY c.from_date DESC`,
        [consultant.id, req.companyId, periodToStr, periodFromStr]
      );
      
      if (contractsResult.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(400).json({ 
          error: `No contract found for ${consultant.first_name} ${consultant.last_name} covering ${monthName} ${year}. ` +
                 `Please ensure there is a contract with dates that include this period.`
        });
      }
      
      // ✅ If multiple contracts, require manual selection
      if (contractsResult.rows.length > 1) {
        await client.query('ROLLBACK');
        return res.status(400).json({ 
          error: 'Multiple contracts found for this period. Please select a contract first.',
          requiresContractSelection: true,
          contracts: contractsResult.rows.map(c => ({
            id: c.id,
            contract_number: c.contract_number,
            client_company_name: c.client_company_name,
            from_date: c.from_date,
            to_date: c.to_date
          }))
        });
      }
      
      // Single contract - use it
      contract = contractsResult.rows[0];
    }
    
    console.log(`Using contract: ${contract.contract_number} (${contract.from_date} to ${contract.to_date})`);

    // ✅ SMART GUARD: check which invoice types already exist (non-credited)
    const existingInvoices = await client.query(
      `SELECT id, invoice_number, invoice_type FROM invoices 
       WHERE timesheet_id = $1 AND company_id = $2 AND invoice_type_detail != 'credit_note' AND status != 'credited'`,
      [id, req.companyId]
    );
    const existingTypes = existingInvoices.rows.map(r => r.invoice_type);
    const needConsultant = !existingTypes.includes('consultant');
    const needClient = !existingTypes.includes('client');

    if (!needConsultant && !needClient) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: `Invoices already exist for this timesheet (${existingInvoices.rows.map(r => r.invoice_number).join(', ')})`,
        existing_invoice_id: existingInvoices.rows[0].id
      });
    }

    // Lock the invoices table for this company to prevent race conditions
    await client.query(
      'SELECT id FROM invoices WHERE company_id = $1 FOR UPDATE',
      [req.companyId]
    );

    // Get consultant full name for invoice numbering (remove spaces and special chars)
    const consultantFullName = (consultant.first_name + consultant.last_name)
      .replace(/[^a-zA-Z0-9]/g, '');
    
    let consultantInvoiceResult = null;
    let clientInvoiceResult = null;

    // ── CONSULTANT INVOICE ──────────────────────────────────────────────────
    if (needConsultant) {
      const consultantInvoiceCountResult = await client.query(
        `SELECT COUNT(*) FROM invoices i
         JOIN contracts c ON i.contract_id = c.id
         WHERE i.company_id = $1 AND i.invoice_type = 'consultant' AND c.consultant_id = $2`,
        [req.companyId, consultant.id]
      );
      const consultantInvoiceCount = parseInt(consultantInvoiceCountResult.rows[0].count);
      const consultantInvoiceNumber = `INV-${year}-${String(consultantInvoiceCount + 1).padStart(4, '0')}-${consultantFullName}`;
      
      const consultantDailyRate = parseFloat(contract.purchase_price);
      const consultantSubtotal = Math.round(consultantDailyRate * daysWorked * 100) / 100;
      const consultantVatRate = contract.consultant_vat_enabled && contract.consultant_vat_rate 
        ? parseFloat(contract.consultant_vat_rate) : 0;
      const consultantVatAmount = Math.round(consultantSubtotal * (consultantVatRate / 100) * 100) / 100;
      const consultantTotal = Math.round((consultantSubtotal + consultantVatAmount) * 100) / 100;

      consultantInvoiceResult = await client.query(
        `INSERT INTO invoices (
          company_id, contract_id, invoice_number, invoice_date, 
          period_from, period_to, days_worked, daily_rate, 
          subtotal, vat_rate, vat_enabled, vat_amount, total_amount, 
          invoice_type, status, timesheet_id
        ) VALUES ($1, $2, $3, CURRENT_DATE, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        RETURNING *`,
        [
          req.companyId, contract.id, consultantInvoiceNumber,
          periodFrom, periodTo, daysWorked, consultantDailyRate,
          consultantSubtotal, consultantVatRate, contract.consultant_vat_enabled || false,
          consultantVatAmount, consultantTotal, 'consultant', 'draft', id
        ]
      );
    }

    // ── CLIENT INVOICE ──────────────────────────────────────────────────────
    if (needClient) {
      const clientInvoiceCountResult = await client.query(
        `SELECT COUNT(*) FROM invoices WHERE company_id = $1 AND invoice_type = 'client'`,
        [req.companyId]
      );
      const clientInvoiceCount = parseInt(clientInvoiceCountResult.rows[0].count);
      const clientInvoiceNumber = `INV-${year}-${String(clientInvoiceCount + 1).padStart(4, '0')}`;

      const clientDailyRate = parseFloat(contract.sell_price);
      const clientSubtotal = Math.round(clientDailyRate * daysWorked * 100) / 100;
      const clientVatRate = contract.vat_enabled && contract.vat_rate 
        ? parseFloat(contract.vat_rate) : 0;
      const clientVatAmount = Math.round(clientSubtotal * (clientVatRate / 100) * 100) / 100;
      const clientTotal = Math.round((clientSubtotal + clientVatAmount) * 100) / 100;

      clientInvoiceResult = await client.query(
        `INSERT INTO invoices (
          company_id, contract_id, invoice_number, invoice_date, 
          period_from, period_to, days_worked, daily_rate, 
          subtotal, vat_rate, vat_enabled, vat_amount, total_amount, 
          invoice_type, status, timesheet_id
        ) VALUES ($1, $2, $3, CURRENT_DATE, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        RETURNING *`,
        [
          req.companyId, contract.id, clientInvoiceNumber,
          periodFrom, periodTo, daysWorked, clientDailyRate,
          clientSubtotal, clientVatRate, contract.vat_enabled || false,
          clientVatAmount, clientTotal, 'client', 'draft', id
        ]
      );
    }
    
    // Mark timesheet as invoiced
    await client.query(
      'UPDATE automation_logs SET invoice_generated = true WHERE id = $1',
      [id]
    );
    
    // Commit transaction
    await client.query('COMMIT');
    
    console.log('✅ SUCCESS: Invoices created for contract:', contract.contract_number, 
                'timesheet_id:', id, 'daysWorked:', daysWorked, 'period:', `${monthName} ${year}`);
    
    await logAudit(req.companyId, req.user.id, req.user.email,
      'GENERATE_INVOICE', 'timesheet', parseInt(id),
      { contract_number: contract.contract_number, month: timesheet.month,
        consultant_invoice: consultantInvoiceResult?.rows[0]?.invoice_number || 'skipped',
        client_invoice: clientInvoiceResult?.rows[0]?.invoice_number || 'skipped' });

    res.json({ 
      message: needConsultant && needClient ? 'Invoices generated successfully'
              : needConsultant ? 'Consultant invoice generated (client already existed)'
              : 'Client invoice generated (consultant already existed)',
      consultantInvoice: consultantInvoiceResult?.rows[0] || null,
      clientInvoice: clientInvoiceResult?.rows[0] || null,
      matchedContract: {
        id: contract.id,
        contract_number: contract.contract_number,
        from_date: contract.from_date,
        to_date: contract.to_date
      }
    });
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error generating invoice:', error);
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

// ============================================
// NEW ENDPOINT: Get timesheet history with linked invoices
// ============================================
app.get('/api/timesheets/history', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT DISTINCT ON (al.id)
        al.*,
        c.first_name as consultant_first_name,
        c.last_name as consultant_last_name,
        c.company_name as consultant_company_name,
        c.id as consultant_id,
        -- Get consultant invoice
        ci.id as consultant_invoice_id,
        ci.invoice_number as consultant_invoice_number,
        ci.pdf_url as consultant_invoice_pdf_url,
        ci.total_amount as consultant_invoice_total,
        ci.status as consultant_invoice_status,
        -- Get client invoice
        cli.id as client_invoice_id,
        cli.invoice_number as client_invoice_number,
        cli.pdf_url as client_invoice_pdf_url,
        cli.total_amount as client_invoice_total,
        cli.status as client_invoice_status
      FROM automation_logs al
      LEFT JOIN consultants c ON LOWER(TRIM(al.sender_email)) = LOWER(TRIM(c.email)) AND c.company_id = $1 AND c.deleted_at IS NULL
      LEFT JOIN invoices ci ON ci.timesheet_id = al.id AND ci.invoice_type = 'consultant' AND ci.company_id = $1
      LEFT JOIN invoices cli ON cli.timesheet_id = al.id AND cli.invoice_type = 'client' AND cli.company_id = $1
      WHERE al.company_id = $1
      ORDER BY al.id, al.created_at DESC
    `, [req.companyId]);

    res.json(result.rows);
  } catch (error) {
    console.error('Get timesheet history error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Get all invoices — with auto overdue detection
app.get('/api/invoices', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { limit, offset, search, type, status } = req.query;
    const useLimit = limit ? parseInt(limit) : null;
    const useOffset = offset ? parseInt(offset) : 0;
    const searchTerm = search ? search.trim() : '';

    // Auto-mark overdue: sent invoices past due_date become overdue
    await pool.query(`
      UPDATE invoices 
      SET status = 'overdue'
      WHERE company_id = $1
        AND status = 'sent'
        AND due_date IS NOT NULL
        AND due_date < CURRENT_DATE
    `, [req.companyId]);

    const params = [req.companyId];
    let whereClause = 'WHERE i.company_id = $1';

    if (searchTerm) {
      params.push(`%${searchTerm}%`);
      const p = params.length;
      whereClause += ` AND (
        i.invoice_number ILIKE $${p} OR
        cons.first_name ILIKE $${p} OR
        cons.last_name ILIKE $${p} OR
        cons.company_name ILIKE $${p} OR
        cli.first_name ILIKE $${p} OR
        cli.last_name ILIKE $${p} OR
        cli.company_name ILIKE $${p} OR
        CONCAT(cons.first_name, ' ', cons.last_name) ILIKE $${p} OR
        CONCAT(cli.first_name, ' ', cli.last_name) ILIKE $${p}
      )`;
    }

    // Type filter: consultant | client
    if (type && type !== 'all') {
      params.push(type);
      whereClause += ` AND i.invoice_type = $${params.length}`;
    }

    // Status filter: draft | sent | paid | overdue | credited | credit_note
    if (status && status !== 'all') {
      if (status === 'credit_note') {
        whereClause += ` AND i.invoice_type_detail = 'credit_note'`;
      } else {
        params.push(status);
        whereClause += ` AND i.status = $${params.length}`;
      }
    }

    const baseQuery = `
FROM invoices i
JOIN contracts c ON i.contract_id = c.id
JOIN consultants cons ON c.consultant_id = cons.id
JOIN clients cli ON c.client_id = cli.id
${whereClause}`;

    const countResult = await pool.query(`SELECT COUNT(*) ${baseQuery}`, params);
    const total = parseInt(countResult.rows[0].count);

    const selectParams = [...params];
    let query = `SELECT i.*, 
       c.consultant_contract_id, 
       c.client_contract_id,
       cons.first_name as consultant_first_name,
       cons.last_name as consultant_last_name,
       cons.company_name as consultant_company_name,
       cli.first_name as client_first_name,
       cli.last_name as client_last_name,
       cli.company_name as client_company_name
${baseQuery}
ORDER BY i.created_at DESC, i.id DESC`;

    if (useLimit) {
      selectParams.push(useLimit);
      query += ` LIMIT $${selectParams.length}`;
      selectParams.push(useOffset);
      query += ` OFFSET $${selectParams.length}`;
    }

    const result = await pool.query(query, selectParams);
    res.json(useLimit ? { data: result.rows, total, limit: useLimit, offset: useOffset } : result.rows);
  } catch (error) {
    console.error('Get invoices error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PATCH invoice status (mark as paid, sent, draft, overdue)
app.patch('/api/invoices/:id/status', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, paid_at, due_date } = req.body;

    const allowed = ['draft', 'sent', 'paid', 'overdue'];
    if (!allowed.includes(status)) {
      return res.status(400).json({ error: `Status must be one of: ${allowed.join(', ')}` });
    }

    const isPaid = status === 'paid';
    const paidAtValue = isPaid ? (paid_at || new Date().toISOString()) : null;

    const result = await pool.query(`
      UPDATE invoices
      SET status = $1,
          paid_at = CASE WHEN $2 THEN $3::timestamptz ELSE paid_at END,
          due_date = COALESCE($4::date, due_date),
          updated_at = NOW()
      WHERE id = $5 AND company_id = $6
      RETURNING *
    `, [status, isPaid, paidAtValue, due_date || null, id, req.companyId]);

    if (result.rows.length === 0) return res.status(404).json({ error: 'Invoice not found' });

    await logAudit(req.companyId, req.user?.id, req.user?.email,
      `INVOICE_${status.toUpperCase()}`, 'invoice', parseInt(id),
      { invoice_number: result.rows[0].invoice_number, status });

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Invoice status update error:', error);
    res.status(500).json({ error: error.message });
  }
});


// N8N Integration - Webhook endpoint
app.post('/api/n8n/automation-data', async (req, res) => {
  try {
    const {
      timestamp, senderEmail, recipientEmail, personName, month,
      emailHours, emailDays, pdfHours, pdfDays,
      hoursDiff, daysDiff, hoursStatus, daysStatus, status,
      timesheetFileUrl, companyId: directCompanyId,
      additionalFiles, flaggedForReview, notes
    } = req.body;

    // ✅ Priority 1: Use companyId directly from N8N payload (most reliable)
    let companyId = directCompanyId || null;
    
    // ✅ Priority 2: Find company by recipient email (timesheet_email setting)
    if (!companyId && recipientEmail) {
      const companyResult = await pool.query(
        'SELECT id FROM companies WHERE LOWER(timesheet_email) = LOWER($1)',
        [recipientEmail.trim()]
      );
      if (companyResult.rows.length > 0) {
        companyId = companyResult.rows[0].id;
      } else {
        console.warn(`No company found for timesheet email: ${recipientEmail}`);
      }
    }
    
    // ✅ Priority 3: Fallback - match by sender email to consultant (exclude soft-deleted)
    if (!companyId && senderEmail) {
      const consultantResult = await pool.query(
        'SELECT company_id FROM consultants WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL LIMIT 1',
        [senderEmail.trim()]
      );
      if (consultantResult.rows.length > 0) {
        companyId = consultantResult.rows[0].company_id;
      }
    }
    
    // ✅ Reject if no company could be determined
    if (!companyId) {
      console.error(`Could not determine company for timesheet from: ${senderEmail}`);
      return res.status(400).json({ 
        error: 'Could not determine company. Please include companyId in the payload.',
        senderEmail,
        recipientEmail
      });
    }

    // Normalize additionalFiles — accept array or JSON string
    let additionalFilesArr = [];
    if (Array.isArray(additionalFiles)) {
      additionalFilesArr = additionalFiles.filter(Boolean);
    } else if (typeof additionalFiles === 'string') {
      try { additionalFilesArr = JSON.parse(additionalFiles).filter(Boolean); } catch {}
    }

    const result = await pool.query(`
      INSERT INTO automation_logs 
      (sender_email, recipient_email, person_name, month, email_hours, email_days,
       pdf_hours, pdf_days, hours_diff, days_diff, hours_status, days_status, 
       status, company_id, timesheet_file_url, additional_files, flagged_for_review, notes, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, NOW())
      RETURNING *
    `, [senderEmail, recipientEmail, personName, month, emailHours, emailDays,
        pdfHours, pdfDays, hoursDiff, daysDiff, hoursStatus, daysStatus, 
        status, companyId, timesheetFileUrl || null, JSON.stringify(additionalFilesArr),
        flaggedForReview === 'true' || flaggedForReview === true || false,
        notes || null]);

    // Send confirmation email to consultant (non-blocking)
    if (senderEmail && month) {
      try {
        const settingsResult = await pool.query('SELECT * FROM companies WHERE id = $1', [companyId]);
        if (settingsResult.rows.length > 0) {
          await sendTimesheetConfirmation(senderEmail, personName, month, settingsResult.rows[0]);
          if (process.env.NODE_ENV !== 'production') console.log('📧 Confirmation email sent to:', senderEmail);
        }
      } catch (emailErr) {
        console.error('Confirmation email failed (non-critical):', emailErr.message);
      }
    }

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('N8N webhook error:', error.message);
    console.error('N8N webhook error detail:', error.detail || error.code || '');
    res.status(500).json({ error: 'Internal server error', detail: error.message });
  }
});
// Get automation logs
app.get('/api/automation-logs', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM automation_logs 
      ORDER BY created_at DESC 
      LIMIT 100
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Get automation logs error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update invoice number
app.put('/api/invoices/:id/number', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    const { invoiceNumber } = req.body;

    if (!invoiceNumber || !invoiceNumber.trim()) {
      return res.status(400).json({ error: 'Invoice number is required' });
    }

    // Check if invoice belongs to user's company
    const checkResult = await pool.query(
      'SELECT id FROM invoices WHERE id = $1 AND company_id = $2',
      [id, req.companyId]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Invoice not found' });
    }

    // Update invoice number
    const result = await pool.query(
      'UPDATE invoices SET invoice_number = $1, updated_at = NOW() WHERE id = $2 RETURNING *',
      [invoiceNumber.trim(), id]
    );

    res.json({ message: 'Invoice number updated successfully', invoice: result.rows[0] });
  } catch (error) {
    console.error('Update invoice number error:', error);
    
    if (error.code === '23505') {
      res.status(400).json({ error: 'Invoice number already exists' });
    } else {
      res.status(500).json({ error: error.message });
    }
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Delete a timesheet record (for problematic entries like no_pdf, multiple_pdfs)
app.delete('/api/timesheets/:id', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Verify timesheet belongs to user's company
    const checkResult = await pool.query(
      `SELECT al.* FROM automation_logs al
       LEFT JOIN consultants c ON LOWER(TRIM(al.sender_email)) = LOWER(TRIM(c.email)) AND c.deleted_at IS NULL
       WHERE al.id = $1 AND (al.company_id = $2 OR c.company_id = $2)`,
      [id, req.companyId]
    );
    
    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Timesheet not found' });
    }
    
    const timesheet = checkResult.rows[0];
    
    // Don't allow deleting if invoice was already generated
    if (timesheet.invoice_generated) {
      return res.status(400).json({ 
        error: 'Cannot delete timesheet that has been invoiced' 
      });
    }
    
    // Delete the timesheet
    await pool.query('DELETE FROM automation_logs WHERE id = $1', [id]);
    
    console.log('🗑️ Deleted timesheet:', id, 'status:', timesheet.status);
    
    await logAudit(req.companyId, req.user.id, req.user.email,
      'DELETE_TIMESHEET', 'timesheet', parseInt(id),
      { sender_email: timesheet.sender_email, month: timesheet.month, status: timesheet.status });

    res.json({ message: 'Timesheet deleted successfully' });
  } catch (error) {
    console.error('Delete timesheet error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get company settings
app.get('/api/company/settings', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, address, representative_name, timesheet_deadline_day, 
              company_vat, company_email, timesheet_email, default_vat_rate, 
              bank_name, bank_iban, bank_swift, bank_address,
              smtp_host, smtp_port, smtp_username, smtp_password,
              smtp_from_email, smtp_from_name, smtp_secure,
              COALESCE(invoice_template, 'classic') as invoice_template,
              peppol_enabled, peppol_provider, peppol_sender_id, peppol_environment, country_code, peppol_legal_entity_id,
              (peppol_api_key IS NOT NULL AND peppol_api_key != '') as peppol_api_key_set
       FROM companies WHERE id = $1`,
      [req.companyId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Company not found' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Get company settings error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Update company settings
app.put('/api/company/settings', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const { 
      name, address, representative_name, timesheet_deadline_day, 
      company_vat, company_email, timesheet_email, default_vat_rate,
      bank_name, bank_iban, bank_swift, bank_address,
      smtp_host, smtp_port, smtp_username, smtp_password,
      smtp_from_email, smtp_from_name, smtp_secure,
      invoice_template, contract_renewal_alert_days, payment_terms_days,
      peppol_enabled, peppol_provider, peppol_api_key, peppol_sender_id, peppol_environment, country_code, peppol_legal_entity_id
    } = req.body;
    
    const result = await pool.query(
      `UPDATE companies 
       SET name = $1, address = $2, representative_name = $3, timesheet_deadline_day = $4, 
           company_vat = $5, company_email = $6, timesheet_email = $7, default_vat_rate = $8,  
           bank_name = $9, bank_iban = $10, bank_swift = $11, bank_address = $12,
           smtp_host = $13, smtp_port = $14, smtp_username = $15, smtp_password = $16,
           smtp_from_email = $17, smtp_from_name = $18, smtp_secure = $19, 
           invoice_template = $20, contract_renewal_alert_days = $21, payment_terms_days = $22,
           peppol_enabled = $23, peppol_provider = $24,
           peppol_api_key = CASE WHEN $25::text IS NOT NULL AND $25::text != '' THEN $25::text ELSE peppol_api_key END,
           peppol_sender_id = $26, peppol_environment = $27, country_code = $28,
           peppol_legal_entity_id = $29, updated_at = NOW()
       WHERE id = $30
       RETURNING *`,
      [name, address, representative_name, timesheet_deadline_day, 
       company_vat, company_email, timesheet_email, default_vat_rate,
       bank_name, bank_iban, bank_swift, bank_address,
       smtp_host, smtp_port, smtp_username, smtp_password,
       smtp_from_email, smtp_from_name, smtp_secure,
       invoice_template || 'classic',
       contract_renewal_alert_days != null ? parseInt(contract_renewal_alert_days) : 30,
       payment_terms_days != null ? parseInt(payment_terms_days) : 30,
       peppol_enabled === true || peppol_enabled === 'true',
       peppol_provider || null,
       peppol_api_key || null,  // only update if provided
       peppol_sender_id || null,
       peppol_environment || 'mock',
       country_code || 'BE',
       peppol_legal_entity_id || null,
       req.companyId]
    );
    
    res.json({ message: 'Settings updated successfully', company: result.rows[0] });
  } catch (error) {
    console.error('Update company settings error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get ALL timesheets (including processed ones) - for invoice viewing
app.get('/api/timesheets/all', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT al.*,
             c.first_name as consultant_first_name,
             c.last_name as consultant_last_name,
             c.company_name as consultant_company_name,
             c.id as consultant_id,
             CASE WHEN c.id IS NOT NULL THEN true ELSE false END as consultant_matched
      FROM automation_logs al
      LEFT JOIN consultants c ON al.sender_email = c.email AND c.company_id = $1 AND c.deleted_at IS NULL
      WHERE al.company_id = $1 OR (al.sender_email = c.email AND c.company_id = $1)
      ORDER BY al.created_at DESC
    `, [req.companyId]);

    res.json(result.rows);
  } catch (error) {
    console.error('Get all timesheets error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get timesheet status for all active consultants
app.get('/api/timesheets/status', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const settingsResult = await pool.query(
      'SELECT timesheet_deadline_day FROM companies WHERE id = $1',
      [req.companyId]
    );
    
    const deadlineDay = settingsResult.rows[0]?.timesheet_deadline_day || 15;
    const now = new Date();
    const currentDay = now.getDate();
    const checkingDate = currentDay <= deadlineDay 
      ? new Date(now.getFullYear(), now.getMonth() - 1, 1)
      : new Date(now.getFullYear(), now.getMonth(), 1);
    
    const checkingMonth = checkingDate.toLocaleDateString('en-US', { month: 'long' });
    const checkingYear = checkingDate.getFullYear();
    const deadlineDate = new Date(now.getFullYear(), now.getMonth(), deadlineDay);
    const isOverdue = now > deadlineDate;
    
    // Calculate first and last day of the checking month
    const firstDayOfMonth = new Date(checkingYear, checkingDate.getMonth(), 1);
    const lastDayOfMonth = new Date(checkingYear, checkingDate.getMonth() + 1, 0);
    const firstDayStr = firstDayOfMonth.toISOString().split('T')[0];
    const lastDayStr = lastDayOfMonth.toISOString().split('T')[0];
    
    // ✅ Get all contracts that overlap with the checking month (exclude soft-deleted)
    const contractsResult = await pool.query(
      `SELECT c.id as contract_id, c.contract_number, c.from_date, c.to_date,
              c.purchase_price, c.sell_price,
              cons.id as consultant_id, cons.first_name, cons.last_name, 
              cons.company_name as consultant_company, cons.email as consultant_email,
              cli.id as client_id, cli.first_name as client_first_name, cli.last_name as client_last_name,
              cli.company_name as client_company
       FROM contracts c
       JOIN consultants cons ON c.consultant_id = cons.id
       JOIN clients cli ON c.client_id = cli.id
       WHERE c.company_id = $1 
         AND c.from_date <= $2 
         AND c.to_date >= $3
         AND c.deleted_at IS NULL
         AND cons.deleted_at IS NULL
         AND cli.deleted_at IS NULL
       ORDER BY cons.last_name, cons.first_name, c.from_date`,
      [req.companyId, lastDayStr, firstDayStr]
    );
    
    // Get all timesheets for this company
    const timesheetsResult = await pool.query(
      `SELECT al.* FROM automation_logs al WHERE al.company_id = $1
       UNION
       SELECT al.* FROM automation_logs al
       INNER JOIN consultants c ON LOWER(TRIM(al.sender_email)) = LOWER(TRIM(c.email))
       WHERE c.company_id = $1 AND c.deleted_at IS NULL
       ORDER BY created_at DESC`,
      [req.companyId]
    );
    
    // Map contracts to their status
    const contractStatuses = contractsResult.rows.map(contract => {
      const normalizedConsultantEmail = contract.consultant_email?.trim().toLowerCase();
      
      // Find timesheet for this contract (either by contract_id or by email + month)
      const timesheet = timesheetsResult.rows.find(ts => {
        // First check if timesheet is directly assigned to this contract
        if (ts.contract_id === contract.contract_id) {
          return ts.month?.toLowerCase() === checkingMonth.toLowerCase();
        }
        
        // Otherwise match by email + month (for unassigned timesheets)
        const normalizedSenderEmail = ts.sender_email?.trim().toLowerCase();
        if (normalizedSenderEmail !== normalizedConsultantEmail) return false;
        if (ts.contract_id) return false; // Skip if already assigned to another contract
        if (ts.month) return ts.month.toLowerCase() === checkingMonth.toLowerCase();
        
        // Fallback: estimate month from created_at
        const createdDate = new Date(ts.created_at);
        const estimatedMonth = createdDate.toLocaleDateString('en-US', { month: 'long' });
        return estimatedMonth.toLowerCase() === checkingMonth.toLowerCase();
      });
      
      // Check for invoiced timesheet
      const invoicedTimesheet = timesheetsResult.rows.find(ts => {
        if (ts.contract_id === contract.contract_id && ts.invoice_generated) {
          return ts.month?.toLowerCase() === checkingMonth.toLowerCase();
        }
        return false;
      });
      
      let status;
      if (timesheet || invoicedTimesheet) status = 'received';
      else if (isOverdue) status = 'overdue';
      else status = 'waiting';
      
      // Calculate contract period within the month
      const contractStart = new Date(contract.from_date);
      const contractEnd = new Date(contract.to_date);
      const periodStart = contractStart > firstDayOfMonth ? contractStart : firstDayOfMonth;
      const periodEnd = contractEnd < lastDayOfMonth ? contractEnd : lastDayOfMonth;
      
      return {
        contract_id: contract.contract_id,
        contract_number: contract.contract_number,
        contract_from: contract.from_date,
        contract_to: contract.to_date,
        period_start: periodStart.toISOString().split('T')[0],
        period_end: periodEnd.toISOString().split('T')[0],
        consultant_id: contract.consultant_id,
        consultant_name: `${contract.first_name} ${contract.last_name}`,
        consultant_email: contract.consultant_email,
        consultant_company: contract.consultant_company,
        client_id: contract.client_id,
        client_name: contract.client_company || `${contract.client_first_name} ${contract.client_last_name}`,
        status,
        checking_month: checkingMonth,
        checking_year: checkingYear,
        has_timesheet: !!(timesheet || invoicedTimesheet),
        timesheet_id: timesheet?.id || invoicedTimesheet?.id || null,
        timesheet_processed: (timesheet?.month || invoicedTimesheet?.month) ? true : false,
        invoice_generated: invoicedTimesheet?.invoice_generated || timesheet?.invoice_generated || false
      };
    });
    
    // Also return legacy consultants array for backward compatibility
    const uniqueConsultants = [...new Map(contractsResult.rows.map(c => [c.consultant_id, {
      id: c.consultant_id,
      first_name: c.first_name,
      last_name: c.last_name,
      company_name: c.consultant_company,
      email: c.consultant_email
    }])).values()];
    
    const consultants = uniqueConsultants.map(consultant => {
      const consultantContracts = contractStatuses.filter(c => c.consultant_id === consultant.id);
      const hasAnyTimesheet = consultantContracts.some(c => c.has_timesheet);
      const allInvoiced = consultantContracts.every(c => c.invoice_generated);
      
      let status;
      if (hasAnyTimesheet) status = 'received';
      else if (isOverdue) status = 'overdue';
      else status = 'waiting';
      
      return {
        ...consultant,
        status,
        checking_month: checkingMonth,
        checking_year: checkingYear,
        has_timesheet: hasAnyTimesheet,
        timesheet_processed: consultantContracts.some(c => c.timesheet_processed),
        invoice_generated: allInvoiced,
        expected_timesheets: consultantContracts.length // How many timesheets we expect
      };
    });
    
    res.json({
      checking_month: checkingMonth,
      checking_year: checkingYear,
      deadline_day: deadlineDay,
      deadline_date: deadlineDate.toISOString(),
      is_overdue: isOverdue,
      contracts: contractStatuses,
      consultants
    });
  } catch (error) {
    console.error('Timesheet status error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Update invoice VAT rate
app.put('/api/invoices/:id/vat', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    const { vatRate } = req.body;
    
    const invoiceResult = await pool.query(
      'SELECT * FROM invoices WHERE id = $1 AND company_id = $2',
      [id, req.companyId]
    );
    
    if (invoiceResult.rows.length === 0) {
      return res.status(404).json({ error: 'Invoice not found' });
    }
    
    const invoice = invoiceResult.rows[0];
    const subtotal = parseFloat(invoice.subtotal);
    const vatEnabled = invoice.vat_enabled !== false;
    const newVatAmount = vatEnabled ? (subtotal * vatRate / 100) : 0;
    const newTotal = subtotal + newVatAmount;
    
    const result = await pool.query(
      `UPDATE invoices SET vat_rate = $1, vat_amount = $2, total_amount = $3, updated_at = NOW()
       WHERE id = $4 AND company_id = $5 RETURNING *`,
      [vatRate, newVatAmount, newTotal, id, req.companyId]
    );
    
    res.json({ message: 'VAT rate updated successfully', invoice: result.rows[0] });
  } catch (error) {
    console.error('Update VAT rate error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Toggle VAT enabled/disabled
app.put('/api/invoices/:id/vat-toggle', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    const { vatEnabled } = req.body;
    
    const invoiceResult = await pool.query(
      'SELECT * FROM invoices WHERE id = $1 AND company_id = $2',
      [id, req.companyId]
    );
    
    if (invoiceResult.rows.length === 0) {
      return res.status(404).json({ error: 'Invoice not found' });
    }
    
    const invoice = invoiceResult.rows[0];
    const subtotal = parseFloat(invoice.subtotal);
    const vatRate = parseFloat(invoice.vat_rate);
    const newVatAmount = vatEnabled ? (subtotal * vatRate / 100) : 0;
    const newTotal = subtotal + newVatAmount;
    
    const result = await pool.query(
      `UPDATE invoices SET vat_enabled = $1, vat_amount = $2, total_amount = $3, updated_at = NOW()
       WHERE id = $4 AND company_id = $5 RETURNING *`,
      [vatEnabled, newVatAmount, newTotal, id, req.companyId]
    );
    
    res.json({ message: `VAT ${vatEnabled ? 'enabled' : 'disabled'} successfully`, invoice: result.rows[0] });
  } catch (error) {
    console.error('Toggle VAT error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Generate PDF for an invoice
app.post('/api/invoices/:id/generate-pdf', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    const PDFDocument = require('pdfkit');
    
    const invoiceResult = await pool.query(`
      SELECT i.*, c.consultant_id, c.client_id, c.consultant_contract_id, c.client_contract_id,
             cons.first_name as consultant_first_name, cons.last_name as consultant_last_name,
             cons.company_name as consultant_company_name, cons.company_address as consultant_company_address,
             cons.company_vat as consultant_company_vat, cons.iban as consultant_iban, cons.swift as consultant_swift,
             cli.first_name as client_first_name, cli.last_name as client_last_name,
             cli.company_name as client_company_name, cli.company_address as client_company_address,
             cli.company_vat as client_company_vat,
             comp.name as company_name, comp.address as company_address, comp.company_vat as company_vat_number,
             comp.representative_name, comp.bank_name, comp.bank_iban, comp.bank_swift, comp.bank_address,
             comp.invoice_template,
             orig.invoice_number as original_invoice_number
      FROM invoices i
      JOIN contracts c ON i.contract_id = c.id
      JOIN consultants cons ON c.consultant_id = cons.id
      JOIN clients cli ON c.client_id = cli.id
      JOIN companies comp ON i.company_id = comp.id
      LEFT JOIN invoices orig ON i.original_invoice_id = orig.id
      WHERE i.id = $1 AND i.company_id = $2
    `, [id, req.companyId]);

    if (invoiceResult.rows.length === 0) {
      return res.status(404).json({ error: 'Invoice not found' });
    }

    const invoice = invoiceResult.rows[0];
    const template = invoice.invoice_template || 'classic';
    
    let fromInfo, toInfo;
    if (invoice.invoice_type === 'consultant') {
      fromInfo = {
        name: `${invoice.consultant_first_name} ${invoice.consultant_last_name}`,
        company: invoice.consultant_company_name, 
        address: invoice.consultant_company_address,
        vat: invoice.consultant_company_vat, 
        iban: invoice.consultant_iban, 
        swift: invoice.consultant_swift
      };
      toInfo = {
        name: invoice.representative_name, 
        company: invoice.company_name,
        address: invoice.company_address, 
        vat: invoice.company_vat_number
      };
    } else {
      fromInfo = {
        name: invoice.representative_name, 
        company: invoice.company_name,
        address: invoice.company_address, 
        vat: invoice.company_vat_number,
        iban: invoice.bank_iban, 
        swift: invoice.bank_swift
      };
      toInfo = {
        name: `${invoice.client_first_name} ${invoice.client_last_name}`,
        company: invoice.client_company_name, 
        address: invoice.client_company_address,
        vat: invoice.client_company_vat
      };
    }

    const doc = new PDFDocument({ margin: 50, size: 'A4' });
    const chunks = [];
    
    doc.on('data', chunk => chunks.push(chunk));
    doc.on('end', async () => {
      const pdfBuffer = Buffer.concat(chunks);
      const bucketName = invoice.invoice_type === 'consultant' ? 'consultant-invoices' : 'client-invoices';
      const fileName = `${invoice.invoice_number.replace(/\//g, '-')}.pdf`;
      
      const { error: uploadError } = await supabase.storage.from(bucketName).upload(fileName, pdfBuffer, { contentType: 'application/pdf', upsert: true });
      if (uploadError) return res.status(500).json({ error: 'Failed to upload PDF' });

      const { data: urlData } = supabase.storage.from(bucketName).getPublicUrl(fileName);
      const pdfUrl = urlData.publicUrl;
      await pool.query('UPDATE invoices SET pdf_url = $1, updated_at = NOW() WHERE id = $2', [pdfUrl, id]);
      res.json({ message: 'PDF generated successfully', pdfUrl });
    });

    const pageWidth = doc.page.width;
    const pageHeight = doc.page.height;
    const margin = 50;
    const invoiceDate = new Date(invoice.period_to).toLocaleDateString('en-GB');
    const periodMonth = new Date(invoice.period_to).toLocaleDateString('en-US', { month: 'long' });

    // Credit note helpers
    const isCreditNote = invoice.invoice_type_detail === 'credit_note';
    const docLabel = isCreditNote ? 'CREDIT NOTE' : 'INVOICE';
    const docColor = isCreditNote ? '#dc2626' : '#1e40af'; // red for CN, blue for invoice

    // Helper function to sanitize text
    const sanitize = (text) => {
      if (!text) return '';
      return text.toString()
        .replace(/[\x00-\x1F\x7F]/g, '')
        .replace(/ÿý/g, '')
        .trim();
    };

    // ========================================
    // TEMPLATE: MODERN (Blue header)
    // ========================================
    if (template === 'modern') {
      doc.rect(0, 0, pageWidth, 120).fill(docColor);
      
      doc.fontSize(24).font('Helvetica-Bold').fillColor('#ffffff')
         .text(sanitize(fromInfo.company), margin, 40, { width: pageWidth - 200 });
      
      doc.roundedRect(pageWidth - 180, 35, 130, 45, 6).fill(docColor);
      doc.fontSize(9).fillColor('#ffffff').font('Helvetica')
         .text(docLabel, pageWidth - 170, 43, { width: 110, align: 'center' });
      doc.fontSize(11).font('Helvetica-Bold')
         .text(sanitize(invoice.invoice_number), pageWidth - 170, 58, { width: 110, align: 'center' });
      
      if (isCreditNote) {
        doc.fontSize(8).fillColor('#fca5a5').font('Helvetica')
           .text(`Ref: ${invoice.original_invoice_id ? 'original invoice' : ''}`, pageWidth - 170, 74, { width: 110, align: 'center' });
      }
      
      doc.fillColor('#64748b').fontSize(10).font('Helvetica')
         .text(`Issue Date: ${invoiceDate}`, margin, 135);
      
      const leftCol = margin;
      const rightCol = pageWidth / 2 + 20;
      
      let billY = 165;
      doc.roundedRect(leftCol - 10, billY - 8, 230, 105, 6).fill('#f8fafc');
      doc.fillColor(docColor).fontSize(9).font('Helvetica-Bold').text('BILL TO', leftCol, billY);
      billY += 18;
      doc.fillColor('#0f172a').fontSize(11).font('Helvetica-Bold')
         .text(sanitize(toInfo.company), leftCol, billY, { width: 210 });
      billY += 18;
      doc.fillColor('#475569').fontSize(10).font('Helvetica')
         .text(sanitize(toInfo.name), leftCol, billY);
      billY += 16;
      doc.text(sanitize(toInfo.address) || '', leftCol, billY, { width: 210, lineGap: 4 });
      billY += 24;
      if (toInfo.vat) {
        doc.fillColor('#64748b').text(`VAT: ${sanitize(toInfo.vat)}`, leftCol, billY);
      }
      
      let fromY = 165;
      doc.roundedRect(rightCol - 10, fromY - 8, 230, 105, 6).fill('#f8fafc');
      doc.fillColor(docColor).fontSize(9).font('Helvetica-Bold').text('FROM', rightCol, fromY);
      fromY += 18;
      doc.fillColor('#0f172a').fontSize(11).font('Helvetica-Bold')
         .text(sanitize(fromInfo.company), rightCol, fromY, { width: 210 });
      fromY += 18;
      doc.fillColor('#475569').fontSize(10).font('Helvetica')
         .text(sanitize(fromInfo.address) || '', rightCol, fromY, { width: 210, lineGap: 4 });
      fromY += 24;
      if (fromInfo.vat) {
        doc.fillColor('#64748b').text(`VAT: ${sanitize(fromInfo.vat)}`, rightCol, fromY);
      }
      
      const tableTop = 295;
      const col1 = margin, col2 = margin + 35, col3 = margin + 280, col4 = margin + 340, col5 = margin + 410;
      
      doc.rect(margin - 5, tableTop - 8, pageWidth - 90, 28).fill(docColor);
      doc.fillColor('#ffffff').fontSize(9).font('Helvetica-Bold');
      doc.text('#', col1, tableTop);
      doc.text('Description', col2, tableTop);
      doc.text('Days', col3, tableTop, { width: 40, align: 'right' });
      doc.text('Rate', col4, tableTop, { width: 50, align: 'right' });
      doc.text('Amount', col5, tableTop, { width: 70, align: 'right' });
      
      const rowTop = tableTop + 32;
      doc.fillColor('#0f172a').fontSize(10).font('Helvetica');
      doc.text('1', col1, rowTop);
      
      if (invoice.invoice_type === 'client') {
        doc.font('Helvetica-Bold')
           .text(`IT Services - ${sanitize(invoice.consultant_first_name)} ${sanitize(invoice.consultant_last_name)}`, col2, rowTop, { width: 230 });
        doc.font('Helvetica').fillColor('#64748b').fontSize(9)
           .text(`${periodMonth} • Contract: ${sanitize(invoice.client_contract_id) || 'N/A'}`, col2, rowTop + 14);
      } else {
        doc.font('Helvetica-Bold')
           .text(`IT Services - ${periodMonth}`, col2, rowTop, { width: 230 });
        doc.font('Helvetica').fillColor('#64748b').fontSize(9)
           .text(`Contract: ${sanitize(invoice.consultant_contract_id) || 'N/A'}`, col2, rowTop + 14);
      }
      
      doc.fillColor('#0f172a').fontSize(10).font('Helvetica');
      doc.text(invoice.days_worked.toString(), col3, rowTop, { width: 40, align: 'right' });
      doc.text(`€${parseFloat(invoice.daily_rate).toFixed(2)}`, col4, rowTop, { width: 50, align: 'right' });
      doc.text(`€${parseFloat(invoice.subtotal).toFixed(2)}`, col5, rowTop, { width: 70, align: 'right' });
      
      let summaryTop = rowTop + 50;
      const summaryCol1 = margin + 280;
      const summaryCol2 = margin + 400;
      
      doc.moveTo(summaryCol1, summaryTop).lineTo(pageWidth - margin, summaryTop).strokeColor('#e2e8f0').lineWidth(1).stroke();
      summaryTop += 12;
      
      if (invoice.vat_enabled) {
        doc.fillColor('#64748b').fontSize(10).font('Helvetica');
        doc.text('Subtotal:', summaryCol1, summaryTop, { width: 100, align: 'right' });
        doc.fillColor('#0f172a').text(`€${parseFloat(invoice.subtotal).toFixed(2)}`, summaryCol2, summaryTop, { width: 70, align: 'right' });
        summaryTop += 18;
        
        doc.fillColor('#64748b').text(`VAT (${parseFloat(invoice.vat_rate).toFixed(0)}%):`, summaryCol1, summaryTop, { width: 100, align: 'right' });
        doc.fillColor('#0f172a').text(`€${parseFloat(invoice.vat_amount).toFixed(2)}`, summaryCol2, summaryTop, { width: 70, align: 'right' });
        summaryTop += 22;
      }
      
      // Total - NO BOX, bold black text with line
      doc.moveTo(summaryCol1, summaryTop).lineTo(pageWidth - margin, summaryTop).strokeColor(docColor).lineWidth(2).stroke();
      summaryTop += 12;
      doc.fillColor('#0f172a').fontSize(12).font('Helvetica-Bold');
      doc.text('TOTAL:', summaryCol1, summaryTop, { width: 100, align: 'right' });
      doc.fontSize(14).text(`€${parseFloat(invoice.total_amount).toFixed(2)}`, summaryCol2, summaryTop - 1, { width: 70, align: 'right' });
      
      const bankTop = summaryTop + 45;
      doc.fillColor(docColor).fontSize(11).font('Helvetica-Bold').text('Payment Details', margin, bankTop);
      doc.moveTo(margin, bankTop + 14).lineTo(margin + 120, bankTop + 14).strokeColor(docColor).lineWidth(2).stroke();
      
      doc.fillColor('#475569').fontSize(10).font('Helvetica');
      doc.text(`IBAN: ${sanitize(fromInfo.iban) || 'N/A'}`, margin, bankTop + 26);
      doc.text(`SWIFT: ${sanitize(fromInfo.swift) || 'N/A'}`, margin, bankTop + 42);
      
      doc.fillColor('#64748b').fontSize(9).font('Helvetica')
         .text('We kindly ask this invoice to be paid within 30 days, mentioning the invoice number.', margin, bankTop + 62, { width: 350 });
      
      doc.fillColor('#94a3b8').fontSize(9).font('Helvetica')
         .text('Thank you for your business!', 0, pageHeight - 50, { align: 'center', width: pageWidth });
    }
    
    // ========================================
    // TEMPLATE: CLASSIC - FIXED SPACING
    // ========================================
    else if (template === 'classic' || !template) {
      // Credit note red banner at top
      if (isCreditNote) {
        doc.rect(0, 0, pageWidth, 8).fill('#dc2626');
      }

      doc.fontSize(20).font('Helvetica-Bold').fillColor('#0f172a')
         .text(sanitize(fromInfo.company), margin, 50);
      
      const leftCol = margin;
      const rightCol = pageWidth / 2 + 20;
      
      // BILL TO
      let yPos = 100;
      doc.fontSize(11).font('Helvetica-Bold').fillColor('#475569').text('BILL TO', leftCol, yPos);
      yPos += 20;
      doc.fontSize(10).font('Helvetica').fillColor('#0f172a');
      doc.text(sanitize(toInfo.company), leftCol, yPos, { width: 220 });
      yPos += 16;
      doc.text(sanitize(toInfo.name), leftCol, yPos);
      yPos += 16;
      const toAddress = sanitize(toInfo.address) || '';
      doc.fillColor('#64748b');
      const toAddressHeight = doc.heightOfString(toAddress, { width: 220 });
      doc.text(toAddress, leftCol, yPos, { width: 220 });
      yPos += toAddressHeight + 10;
      if (toInfo.vat) {
        doc.text(`VAT: ${sanitize(toInfo.vat)}`, leftCol, yPos);
      }

      // FROM
      let fromYPos = 100;
      doc.fillColor('#475569').fontSize(11).font('Helvetica-Bold').text('FROM', rightCol, fromYPos);
      fromYPos += 20;
      doc.fontSize(10).font('Helvetica').fillColor('#0f172a');
      doc.text(sanitize(fromInfo.company), rightCol, fromYPos, { width: 220 });
      fromYPos += 16;
      const fromAddress = sanitize(fromInfo.address) || '';
      doc.fillColor('#64748b');
      const fromAddressHeight = doc.heightOfString(fromAddress, { width: 220 });
      doc.text(fromAddress, rightCol, fromYPos, { width: 220 });
      fromYPos += fromAddressHeight + 10;
      if (fromInfo.vat) {
        doc.text(`VAT: ${sanitize(fromInfo.vat)}`, rightCol, fromYPos);
      }

      // Invoice title - dynamic position
      const titleY = Math.max(yPos, fromYPos) + 30;
      doc.fontSize(16).font('Helvetica-Bold').fillColor(isCreditNote ? '#dc2626' : '#0f172a')
         .text(`${docLabel} ${invoice.invoice_number}`, margin, titleY, { align: 'center', width: pageWidth - (margin * 2) });
      if (isCreditNote) {
        doc.fontSize(10).font('Helvetica').fillColor('#dc2626')
           .text(`Cancels invoice: ${invoice.original_invoice_number || invoice.original_invoice_id}`, margin, titleY + 20, { align: 'center', width: pageWidth - (margin * 2) });
      }
      doc.fontSize(11).font('Helvetica').fillColor('#64748b')
         .text(`Date: ${invoiceDate}`, margin, titleY + (isCreditNote ? 36 : 22), { align: 'center', width: pageWidth - (margin * 2) });

      // Table
      const tableTop = titleY + 60;
      const col1 = margin, col2 = margin + 40, col3 = margin + 280, col4 = margin + 350, col5 = margin + 430;

      doc.fontSize(10).font('Helvetica-Bold').fillColor('#475569');
      doc.text('#', col1, tableTop);
      doc.text('Description', col2, tableTop);
      doc.text('Days', col3, tableTop, { width: 50, align: 'right' });
      doc.text('Rate', col4, tableTop, { width: 60, align: 'right' });
      doc.text('Amount', col5, tableTop, { width: 60, align: 'right' });
      doc.moveTo(margin, tableTop + 14).lineTo(pageWidth - margin, tableTop + 14).strokeColor('#cbd5e1').stroke();

      const rowTop = tableTop + 26;
      doc.fontSize(10).font('Helvetica').fillColor('#0f172a');
      doc.text('1', col1, rowTop);

      if (invoice.invoice_type === 'client') {
        doc.text(`IT Services - ${sanitize(invoice.consultant_first_name)} ${sanitize(invoice.consultant_last_name)} - ${periodMonth}`, col2, rowTop, { width: 230 });
        doc.fillColor('#64748b').fontSize(9).text(`Contract: ${sanitize(invoice.client_contract_id) || 'N/A'}`, col2, rowTop + 13);
      } else {
        doc.text(`IT Services - ${periodMonth}`, col2, rowTop, { width: 230 });
        doc.fillColor('#64748b').fontSize(9).text(`Contract: ${sanitize(invoice.consultant_contract_id) || 'N/A'}`, col2, rowTop + 13);
      }
      
      doc.fillColor('#0f172a').fontSize(10);
      doc.text(invoice.days_worked.toString(), col3, rowTop, { width: 50, align: 'right' });
      doc.text(`€${parseFloat(invoice.daily_rate).toFixed(2)}`, col4, rowTop, { width: 60, align: 'right' });
      doc.text(`€${parseFloat(invoice.subtotal).toFixed(2)}`, col5, rowTop, { width: 60, align: 'right' });

      let summaryTop = rowTop + 45;
      const summaryCol1 = margin + 300;
      const summaryCol2 = margin + 400;
      
      if (invoice.vat_enabled) {
        doc.moveTo(summaryCol1, summaryTop).lineTo(pageWidth - margin, summaryTop).strokeColor('#e2e8f0').stroke();
        summaryTop += 12;
        
        doc.fontSize(10).font('Helvetica').fillColor('#64748b');
        doc.text('Subtotal:', summaryCol1, summaryTop, { width: 80, align: 'right' });
        doc.fillColor('#0f172a').text(`€${parseFloat(invoice.subtotal).toFixed(2)}`, summaryCol2, summaryTop, { width: 70, align: 'right' });
        summaryTop += 16;
        
        doc.fillColor('#64748b').text(`VAT ${parseFloat(invoice.vat_rate).toFixed(0)}%:`, summaryCol1, summaryTop, { width: 80, align: 'right' });
        doc.fillColor('#0f172a').text(`€${parseFloat(invoice.vat_amount).toFixed(2)}`, summaryCol2, summaryTop, { width: 70, align: 'right' });
        summaryTop += 20;
      }

      // Total - NO BOX, bold black
      doc.moveTo(summaryCol1, summaryTop).lineTo(pageWidth - margin, summaryTop).strokeColor('#0f172a').lineWidth(1.5).stroke();
      summaryTop += 12;
      doc.fontSize(12).font('Helvetica-Bold').fillColor('#0f172a');
      doc.text('Total:', summaryCol1, summaryTop, { width: 80, align: 'right' });
      doc.fontSize(13).text(`€${parseFloat(invoice.total_amount).toFixed(2)}`, summaryCol2, summaryTop - 1, { width: 70, align: 'right' });

      const bankTop = summaryTop + 45;
      doc.fontSize(10).font('Helvetica-Bold').fillColor('#475569').text('Payment Details', margin, bankTop);
      doc.fontSize(10).font('Helvetica').fillColor('#0f172a');
      doc.text(`IBAN: ${sanitize(fromInfo.iban) || 'N/A'}`, margin, bankTop + 18);
      doc.text(`SWIFT: ${sanitize(fromInfo.swift) || 'N/A'}`, margin, bankTop + 34);
      
      doc.fillColor('#64748b').fontSize(9)
         .text('We kindly ask this invoice to be paid within 30 days, mentioning the invoice number.', margin, bankTop + 56, { width: 350 });
      
      doc.fillColor('#94a3b8').fontSize(9)
         .text('Thank you for your business!', 0, pageHeight - 50, { align: 'center', width: pageWidth });
    }
    
    // ========================================
    // TEMPLATE: MINIMAL
    // ========================================
    else if (template === 'minimal') {
      doc.moveTo(margin, 40).lineTo(pageWidth - margin, 40).strokeColor(isCreditNote ? '#dc2626' : '#0f172a').lineWidth(isCreditNote ? 3 : 2).stroke();
      
      doc.fontSize(18).font('Helvetica-Bold').fillColor('#0f172a')
         .text(sanitize(fromInfo.company), margin, 55);
      doc.fontSize(11).font('Helvetica').fillColor(isCreditNote ? '#dc2626' : '#64748b')
         .text(`${docLabel} ${invoice.invoice_number}`, margin, 78);
      doc.fillColor('#64748b').text(`Date: ${invoiceDate}`, pageWidth - 180, 78, { width: 130, align: 'right' });
      
      doc.moveTo(margin, 100).lineTo(pageWidth - margin, 100).strokeColor('#e2e8f0').lineWidth(1).stroke();
      
      let yPos = 118;
      const leftCol = margin;
      const rightCol = pageWidth / 2 + 30;
      
      doc.fillColor('#94a3b8').fontSize(9).font('Helvetica').text('BILLED TO', leftCol, yPos);
      yPos += 16;
      doc.fillColor('#0f172a').fontSize(11).font('Helvetica-Bold').text(sanitize(toInfo.company), leftCol, yPos);
      yPos += 16;
      doc.fillColor('#475569').fontSize(10).font('Helvetica').text(sanitize(toInfo.name), leftCol, yPos);
      yPos += 14;
      doc.text(sanitize(toInfo.address) || '', leftCol, yPos, { width: 200, lineGap: 4 });
      yPos += 24;
      if (toInfo.vat) doc.text(`VAT: ${sanitize(toInfo.vat)}`, leftCol, yPos);
      
      let fromY = 118;
      doc.fillColor('#94a3b8').fontSize(9).text('FROM', rightCol, fromY);
      fromY += 16;
      doc.fillColor('#0f172a').fontSize(11).font('Helvetica-Bold').text(sanitize(fromInfo.company), rightCol, fromY);
      fromY += 16;
      doc.fillColor('#475569').fontSize(10).font('Helvetica').text(sanitize(fromInfo.address) || '', rightCol, fromY, { width: 200, lineGap: 4 });
      fromY += 24;
      if (fromInfo.vat) doc.text(`VAT: ${sanitize(fromInfo.vat)}`, rightCol, fromY);
      
      const tableTop = 230;
      doc.moveTo(margin, tableTop).lineTo(pageWidth - margin, tableTop).strokeColor('#0f172a').lineWidth(1).stroke();
      
      const col1 = margin, col2 = margin + 280, col3 = margin + 350, col4 = margin + 430;
      doc.fillColor('#0f172a').fontSize(9).font('Helvetica-Bold');
      doc.text('Description', col1, tableTop + 10);
      doc.text('Days', col2, tableTop + 10, { width: 50, align: 'right' });
      doc.text('Rate', col3, tableTop + 10, { width: 60, align: 'right' });
      doc.text('Amount', col4, tableTop + 10, { width: 60, align: 'right' });
      
      doc.moveTo(margin, tableTop + 26).lineTo(pageWidth - margin, tableTop + 26).strokeColor('#e2e8f0').stroke();
      
      const rowTop = tableTop + 38;
      doc.fillColor('#0f172a').fontSize(10).font('Helvetica');
      if (invoice.invoice_type === 'client') {
        doc.text(`IT Services - ${sanitize(invoice.consultant_first_name)} ${sanitize(invoice.consultant_last_name)} - ${periodMonth}`, col1, rowTop);
        doc.fillColor('#94a3b8').fontSize(9).text(`Contract: ${sanitize(invoice.client_contract_id) || 'N/A'}`, col1, rowTop + 13);
      } else {
        doc.text(`IT Services - ${periodMonth}`, col1, rowTop);
        doc.fillColor('#94a3b8').fontSize(9).text(`Contract: ${sanitize(invoice.consultant_contract_id) || 'N/A'}`, col1, rowTop + 13);
      }
      doc.fillColor('#0f172a').fontSize(10);
      doc.text(invoice.days_worked.toString(), col2, rowTop, { width: 50, align: 'right' });
      doc.text(`€${parseFloat(invoice.daily_rate).toFixed(2)}`, col3, rowTop, { width: 60, align: 'right' });
      doc.text(`€${parseFloat(invoice.subtotal).toFixed(2)}`, col4, rowTop, { width: 60, align: 'right' });
      
      let summaryTop = rowTop + 45;
      const summaryCol1 = margin + 280;
      const summaryCol2 = margin + 390;
      
      doc.moveTo(summaryCol1, summaryTop).lineTo(pageWidth - margin, summaryTop).strokeColor('#e2e8f0').stroke();
      summaryTop += 12;
      
      if (invoice.vat_enabled) {
        doc.fillColor('#64748b').fontSize(10);
        doc.text(`VAT ${parseFloat(invoice.vat_rate).toFixed(0)}%:`, summaryCol1, summaryTop, { width: 90, align: 'right' });
        doc.fillColor('#0f172a').text(`€${parseFloat(invoice.vat_amount).toFixed(2)}`, summaryCol2, summaryTop, { width: 70, align: 'right' });
        summaryTop += 20;
      }
      
      // Total - NO BOX, bold black
      doc.moveTo(summaryCol1, summaryTop).lineTo(pageWidth - margin, summaryTop).strokeColor('#0f172a').lineWidth(1.5).stroke();
      summaryTop += 12;
      doc.fillColor('#0f172a').fontSize(12).font('Helvetica-Bold');
      doc.text('Total:', summaryCol1, summaryTop, { width: 90, align: 'right' });
      doc.fontSize(13).text(`€${parseFloat(invoice.total_amount).toFixed(2)}`, summaryCol2, summaryTop - 1, { width: 70, align: 'right' });
      
      const bankTop = summaryTop + 45;
      doc.fillColor('#94a3b8').fontSize(9).font('Helvetica').text('PAYMENT DETAILS', margin, bankTop);
      doc.fillColor('#475569').fontSize(10);
      doc.text(`IBAN: ${sanitize(fromInfo.iban) || 'N/A'}`, margin, bankTop + 16);
      doc.text(`SWIFT: ${sanitize(fromInfo.swift) || 'N/A'}`, margin, bankTop + 32);
      
      doc.fillColor('#94a3b8').fontSize(9)
         .text('We kindly ask this invoice to be paid within 30 days, mentioning the invoice number.', margin, bankTop + 52, { width: 350 });
    }
    
    // ========================================
    // TEMPLATE: PROFESSIONAL (Green accent)
    // ========================================
    else if (template === 'professional') {
      doc.rect(0, 0, 6, pageHeight).fill(isCreditNote ? '#dc2626' : '#059669');
      
      doc.fontSize(22).font('Helvetica-Bold').fillColor('#0f172a')
         .text(sanitize(fromInfo.company), margin + 10, 45);
      doc.fontSize(10).fillColor('#64748b').font('Helvetica')
         .text(sanitize(fromInfo.address) || '', margin + 10, 72, { width: 250, lineGap: 4 });
      if (fromInfo.vat) doc.text(`VAT: ${sanitize(fromInfo.vat)}`, margin + 10, 100);
      
      doc.roundedRect(pageWidth - 175, 40, 125, 75, 5).fill(isCreditNote ? '#fef2f2' : '#ecfdf5');
      doc.fillColor(isCreditNote ? '#dc2626' : '#059669').fontSize(isCreditNote ? 12 : 16).font('Helvetica-Bold').text(docLabel, pageWidth - 165, 48, { width: 105, align: 'center' });
      doc.fillColor('#0f172a').fontSize(9).font('Helvetica').text(sanitize(invoice.invoice_number), pageWidth - 165, 70, { width: 105, align: 'center' });
      doc.fillColor('#64748b').fontSize(9).text(invoiceDate, pageWidth - 165, 95, { width: 105, align: 'center' });
      
      let yPos = 130;
      doc.fillColor(isCreditNote ? '#dc2626' : '#059669').fontSize(10).font('Helvetica-Bold').text('BILL TO', margin + 10, yPos);
      doc.moveTo(margin + 10, yPos + 13).lineTo(margin + 60, yPos + 13).strokeColor(isCreditNote ? '#dc2626' : '#059669').lineWidth(2).stroke();
      yPos += 24;
      doc.fillColor('#0f172a').fontSize(11).font('Helvetica-Bold').text(sanitize(toInfo.company), margin + 10, yPos);
      yPos += 16;
      doc.fillColor('#475569').fontSize(10).font('Helvetica').text(sanitize(toInfo.name), margin + 10, yPos);
      yPos += 14;
      doc.text(sanitize(toInfo.address) || '', margin + 10, yPos, { width: 250, lineGap: 4 });
      yPos += 26;
      if (toInfo.vat) doc.text(`VAT: ${sanitize(toInfo.vat)}`, margin + 10, yPos);
      
      const tableTop = 265;
      const col1 = margin + 10, col2 = margin + 45, col3 = margin + 280, col4 = margin + 345, col5 = margin + 415;
      
      doc.rect(margin, tableTop - 5, pageWidth - margin - 50, 26).fill('#059669');
      doc.fillColor('#ffffff').fontSize(9).font('Helvetica-Bold');
      doc.text('No.', col1, tableTop + 2);
      doc.text('Service Description', col2, tableTop + 2);
      doc.text('Days', col3, tableTop + 2, { width: 45, align: 'right' });
      doc.text('Rate', col4, tableTop + 2, { width: 50, align: 'right' });
      doc.text('Amount', col5, tableTop + 2, { width: 65, align: 'right' });
      
      const rowTop = tableTop + 32;
      doc.fillColor('#0f172a').fontSize(10).font('Helvetica');
      doc.text('01', col1, rowTop);
      if (invoice.invoice_type === 'client') {
        doc.font('Helvetica-Bold').text(`IT Services - ${sanitize(invoice.consultant_first_name)} ${sanitize(invoice.consultant_last_name)}`, col2, rowTop);
        doc.font('Helvetica').fillColor('#64748b').fontSize(9)
           .text(`${periodMonth} | Contract: ${sanitize(invoice.client_contract_id) || 'N/A'}`, col2, rowTop + 13);
      } else {
        doc.font('Helvetica-Bold').text(`IT Services - ${periodMonth}`, col2, rowTop);
        doc.font('Helvetica').fillColor('#64748b').fontSize(9)
           .text(`Contract: ${sanitize(invoice.consultant_contract_id) || 'N/A'}`, col2, rowTop + 13);
      }
      doc.fillColor('#0f172a').fontSize(10).font('Helvetica');
      doc.text(invoice.days_worked.toString(), col3, rowTop, { width: 45, align: 'right' });
      doc.text(`€${parseFloat(invoice.daily_rate).toFixed(2)}`, col4, rowTop, { width: 50, align: 'right' });
      doc.font('Helvetica-Bold').text(`€${parseFloat(invoice.subtotal).toFixed(2)}`, col5, rowTop, { width: 65, align: 'right' });
      
      let summaryTop = rowTop + 50;
      const summaryCol1 = margin + 270;
      const summaryCol2 = margin + 385;
      
      doc.moveTo(summaryCol1, summaryTop).lineTo(pageWidth - margin, summaryTop).strokeColor('#e2e8f0').lineWidth(1).stroke();
      summaryTop += 12;
      
      if (invoice.vat_enabled) {
        doc.fillColor('#64748b').fontSize(10).font('Helvetica');
        doc.text('Subtotal:', summaryCol1, summaryTop, { width: 95, align: 'right' });
        doc.fillColor('#0f172a').text(`€${parseFloat(invoice.subtotal).toFixed(2)}`, summaryCol2, summaryTop, { width: 70, align: 'right' });
        summaryTop += 16;
        doc.fillColor('#64748b').text(`VAT (${parseFloat(invoice.vat_rate).toFixed(0)}%):`, summaryCol1, summaryTop, { width: 95, align: 'right' });
        doc.fillColor('#0f172a').text(`€${parseFloat(invoice.vat_amount).toFixed(2)}`, summaryCol2, summaryTop, { width: 70, align: 'right' });
        summaryTop += 20;
      }
      
      // Total - NO BOX, bold black with green line
      doc.moveTo(summaryCol1, summaryTop).lineTo(pageWidth - margin, summaryTop).strokeColor('#059669').lineWidth(2).stroke();
      summaryTop += 12;
      doc.fillColor('#0f172a').fontSize(12).font('Helvetica-Bold');
      doc.text('TOTAL DUE:', summaryCol1, summaryTop, { width: 95, align: 'right' });
      doc.fontSize(14).text(`€${parseFloat(invoice.total_amount).toFixed(2)}`, summaryCol2, summaryTop - 1, { width: 70, align: 'right' });
      
      const bankTop = summaryTop + 45;
      doc.roundedRect(margin, bankTop - 8, 260, 85, 5).fill('#ecfdf5');
      doc.fillColor('#059669').fontSize(10).font('Helvetica-Bold').text('Payment Information', margin + 12, bankTop);
      doc.fillColor('#475569').fontSize(10).font('Helvetica');
      doc.text(`IBAN: ${sanitize(fromInfo.iban) || 'N/A'}`, margin + 12, bankTop + 20);
      doc.text(`SWIFT: ${sanitize(fromInfo.swift) || 'N/A'}`, margin + 12, bankTop + 36);
      
      doc.fillColor('#64748b').fontSize(9)
         .text('We kindly ask this invoice to be paid within 30 days,', margin + 12, bankTop + 56);
      doc.text('mentioning the invoice number.', margin + 12, bankTop + 68);
    }

    doc.end();
  } catch (error) {
    console.error('Generate PDF error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Send invoice email
app.post('/api/invoices/:id/send-email', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    
    const invoiceResult = await pool.query(`
      SELECT i.*, cons.email as consultant_email, cons.first_name as consultant_first_name, cons.last_name as consultant_last_name,
             cli.email as client_email, cli.first_name as client_first_name, cli.last_name as client_last_name,
             comp.name as company_name, comp.smtp_host, comp.smtp_port, comp.smtp_username, comp.smtp_password,
             comp.smtp_from_email, comp.smtp_from_name, comp.smtp_secure, comp.address, comp.company_email, comp.representative_name,
             al.timesheet_file_url
      FROM invoices i
      JOIN contracts c ON i.contract_id = c.id
      JOIN consultants cons ON c.consultant_id = cons.id
      JOIN clients cli ON c.client_id = cli.id
      JOIN companies comp ON i.company_id = comp.id
      LEFT JOIN automation_logs al ON al.id = i.timesheet_id
      WHERE i.id = $1 AND i.company_id = $2
    `, [id, req.companyId]);

    if (invoiceResult.rows.length === 0) return res.status(404).json({ error: 'Invoice not found' });

    const invoice = invoiceResult.rows[0];
    if (!invoice.pdf_url) return res.status(400).json({ error: 'Please generate PDF before sending email' });
    
    let recipientEmail, recipientName;
    if (invoice.invoice_type === 'consultant') {
      recipientEmail = invoice.consultant_email;
      recipientName = `${invoice.consultant_first_name} ${invoice.consultant_last_name}`;
    } else {
      recipientEmail = invoice.client_email;
      recipientName = `${invoice.client_first_name} ${invoice.client_last_name}`;
    }
    
    if (!recipientEmail) return res.status(400).json({ error: 'Recipient email not found' });
    
    await sendInvoiceEmail(invoice, invoice, recipientEmail, recipientName);
    
    await pool.query(
      `UPDATE invoices SET email_sent = true, email_sent_at = NOW(), email_sent_to = $1,
       status = CASE WHEN status = 'draft' THEN 'sent' ELSE status END,
       updated_at = NOW() WHERE id = $2`,
      [recipientEmail, id]
    );
    
    res.json({ message: 'Email sent successfully', recipient: recipientEmail });
  } catch (error) {
    console.error('Send email error:', error);
    res.status(500).json({ error: error.message });
  }
});

// User Management Routes (exclude soft-deleted)
app.get('/api/users', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.id, u.email, u.first_name, u.last_name, u.role, u.permissions, u.active, u.created_at, u.last_login
      FROM users u WHERE u.company_id = $1 AND u.deleted_at IS NULL ORDER BY u.created_at DESC
    `, [req.companyId]);
    res.json(result.rows);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/users', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const { email, password, firstName, lastName, role, permissions } = req.body;
    if (!email || !password || !firstName || !lastName) {
      return res.status(400).json({ error: 'Email, password, first name, and last name are required' });
    }

    const userRole = role || 'operator';
    if (!['admin', 'operator'].includes(userRole)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1 AND deleted_at IS NULL', [email.toLowerCase()]);
    if (existingUser.rows.length > 0) return res.status(400).json({ error: 'Email already exists' });

    const hashedPassword = await bcrypt.hash(password, 12);
    const userPermissions = userRole === 'admin' ? DEFAULT_PERMISSIONS.admin : (permissions || DEFAULT_PERMISSIONS.operator);

    const result = await pool.query(`
      INSERT INTO users (email, password_hash, first_name, last_name, company_id, role, permissions, active, created_by, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, true, $8, NOW())
      RETURNING id, email, first_name, last_name, role, permissions, active, created_at
    `, [email.toLowerCase(), hashedPassword, firstName, lastName, req.companyId, userRole, JSON.stringify(userPermissions), req.user.id]);

    res.status(201).json({ message: 'User created successfully', user: result.rows[0] });
  } catch (error) {
    console.error('Create user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/users/:id', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    const { email, firstName, lastName, role, permissions, password } = req.body;

    const targetUser = await pool.query('SELECT * FROM users WHERE id = $1 AND company_id = $2 AND deleted_at IS NULL', [id, req.companyId]);
    if (targetUser.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    if (parseInt(id) === req.user.id && role && role !== targetUser.rows[0].role) {
      return res.status(400).json({ error: 'You cannot change your own role' });
    }

    let finalPermissions = permissions;
    if (role === 'admin') finalPermissions = DEFAULT_PERMISSIONS.admin;

    let updateFields = [], values = [], valueIndex = 1;

    if (email) { updateFields.push(`email = $${valueIndex++}`); values.push(email.toLowerCase()); }
    if (firstName) { updateFields.push(`first_name = $${valueIndex++}`); values.push(firstName); }
    if (lastName) { updateFields.push(`last_name = $${valueIndex++}`); values.push(lastName); }
    if (role) { updateFields.push(`role = $${valueIndex++}`); values.push(role); }
    if (finalPermissions) { updateFields.push(`permissions = $${valueIndex++}`); values.push(JSON.stringify(finalPermissions)); }
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 12);
      updateFields.push(`password_hash = $${valueIndex++}`);
      values.push(hashedPassword);
    }

    if (updateFields.length === 0) return res.status(400).json({ error: 'No fields to update' });

    updateFields.push(`updated_at = NOW()`);
    values.push(id);
    values.push(req.companyId);

    const result = await pool.query(
      `UPDATE users SET ${updateFields.join(', ')} WHERE id = $${valueIndex++} AND company_id = $${valueIndex} AND deleted_at IS NULL RETURNING *`,
      values
    );

    res.json({ message: 'User updated successfully', user: result.rows[0] });
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/users/:id/toggle-active', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    const userCheck = await pool.query('SELECT * FROM users WHERE id = $1 AND company_id = $2 AND deleted_at IS NULL', [id, req.companyId]);
    if (userCheck.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    if (userCheck.rows[0].id === req.user.id) {
      return res.status(400).json({ error: 'You cannot disable your own account' });
    }

    const result = await pool.query('UPDATE users SET active = NOT active, updated_at = NOW() WHERE id = $1 RETURNING *', [id]);
    res.json({ message: `User ${result.rows[0].active ? 'enabled' : 'disabled'} successfully`, user: result.rows[0] });
  } catch (error) {
    console.error('Toggle user active error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE user (SOFT DELETE)
app.delete('/api/users/:id', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    const userCheck = await pool.query('SELECT * FROM users WHERE id = $1 AND company_id = $2 AND deleted_at IS NULL', [id, req.companyId]);
    if (userCheck.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    if (userCheck.rows[0].id === req.user.id) return res.status(400).json({ error: 'You cannot delete your own account' });

    // ✅ SOFT DELETE instead of hard delete
    await pool.query(
      'UPDATE users SET deleted_at = NOW(), deleted_by = $1 WHERE id = $2',
      [req.userId, id]
    );
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Current and new passwords are required' });

    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    const user = result.rows[0];

    const isValid = await bcrypt.compare(currentPassword, user.password_hash);
    if (!isValid) return res.status(401).json({ error: 'Current password is incorrect' });

    const hashedPassword = await bcrypt.hash(newPassword, 12);
    await pool.query('UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2', [hashedPassword, req.user.id]);

    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================
// SUPER ADMIN ROUTES (with soft delete filters)
// =============================================

// Get all companies (super admin only)
app.get('/api/superadmin/companies', authenticateToken, requireSuperAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        c.*,
        (SELECT COUNT(*) FROM users WHERE company_id = c.id AND deleted_at IS NULL) as user_count,
        (SELECT COUNT(*) FROM consultants WHERE company_id = c.id AND deleted_at IS NULL) as consultant_count,
        (SELECT COUNT(*) FROM clients WHERE company_id = c.id AND deleted_at IS NULL) as client_count,
        (SELECT COUNT(*) FROM contracts WHERE company_id = c.id AND deleted_at IS NULL) as contract_count,
        (SELECT COUNT(*) FROM invoices WHERE company_id = c.id) as invoice_count
      FROM companies c
      ORDER BY c.name ASC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Get companies error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get company details with users (super admin only)
app.get('/api/superadmin/companies/:id', authenticateToken, requireSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const companyResult = await pool.query('SELECT * FROM companies WHERE id = $1', [id]);
    if (companyResult.rows.length === 0) {
      return res.status(404).json({ error: 'Company not found' });
    }
    
    const usersResult = await pool.query(
      'SELECT id, email, first_name, last_name, role, active, created_at FROM users WHERE company_id = $1 AND deleted_at IS NULL ORDER BY created_at DESC',
      [id]
    );
    
    res.json({
      company: companyResult.rows[0],
      users: usersResult.rows
    });
  } catch (error) {
    console.error('Get company details error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Generate impersonation token (super admin only)
app.post('/api/superadmin/impersonate/:companyId', authenticateToken, requireSuperAdmin, async (req, res) => {
  try {
    const { companyId } = req.params;
    
    // Verify company exists
    const companyResult = await pool.query('SELECT * FROM companies WHERE id = $1', [companyId]);
    if (companyResult.rows.length === 0) {
      return res.status(404).json({ error: 'Company not found' });
    }
    
    // Get first admin user of that company (or any user) - exclude soft-deleted
    const userResult = await pool.query(
      `SELECT * FROM users WHERE company_id = $1 AND active = true AND deleted_at IS NULL ORDER BY role = 'admin' DESC, created_at ASC LIMIT 1`,
      [companyId]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'No active users in this company' });
    }
    
    const targetUser = userResult.rows[0];
    const company = companyResult.rows[0];
    
    // Generate a token for the target user
    const token = jwt.sign(
      { userId: targetUser.id, companyId: targetUser.company_id, impersonatedBy: req.user.id },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    // Log impersonation
    console.log(`🔐 Super admin ${req.user.email} (ID: ${req.user.id}) impersonating company "${company.name}" (ID: ${companyId}) as user ${targetUser.email}`);
    
    res.json({
      token,
      user: {
        id: targetUser.id,
        email: targetUser.email,
        firstName: targetUser.first_name,
        lastName: targetUser.last_name,
        role: targetUser.role,
        companyId: targetUser.company_id,
        companyName: company.name
      },
      impersonatedBy: {
        id: req.user.id,
        email: req.user.email
      }
    });
  } catch (error) {
    console.error('Impersonate error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create new company (super admin only)
app.post('/api/superadmin/companies', authenticateToken, requireSuperAdmin, async (req, res) => {
  try {
    const { name, email, adminFirstName, adminLastName, adminPassword } = req.body;
    
    if (!name || !email || !adminFirstName || !adminLastName || !adminPassword) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    // Check if company name or admin email already exists
    const existingCompany = await pool.query('SELECT id FROM companies WHERE LOWER(name) = LOWER($1)', [name]);
    if (existingCompany.rows.length > 0) {
      return res.status(400).json({ error: 'Company name already exists' });
    }
    
    const existingUser = await pool.query('SELECT id FROM users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Email already in use' });
    }
    
    // Create company
    const companyResult = await pool.query(
      'INSERT INTO companies (name, created_at) VALUES ($1, CURRENT_TIMESTAMP) RETURNING *',
      [name]
    );
    const newCompany = companyResult.rows[0];
    
    // Create admin user
    const hashedPassword = await bcrypt.hash(adminPassword, 10);
    const userResult = await pool.query(
      `INSERT INTO users (email, password_hash, first_name, last_name, company_id, role, active, created_at) 
       VALUES ($1, $2, $3, $4, $5, 'admin', true, CURRENT_TIMESTAMP) RETURNING id, email, first_name, last_name, role`,
      [email, hashedPassword, adminFirstName, adminLastName, newCompany.id]
    );
    
    res.json({
      company: newCompany,
      admin: userResult.rows[0]
    });
  } catch (error) {
    console.error('Create company error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update company (super admin only)
app.put('/api/superadmin/companies/:id', authenticateToken, requireSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { name } = req.body;
    
    const result = await pool.query(
      'UPDATE companies SET name = $1 WHERE id = $2 RETURNING *',
      [name, id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Company not found' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Update company error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get super admin dashboard stats (with soft delete filters)
app.get('/api/superadmin/stats', authenticateToken, requireSuperAdmin, async (req, res) => {
  try {
    const stats = await pool.query(`
      SELECT 
        (SELECT COUNT(*) FROM companies) as total_companies,
        (SELECT COUNT(*) FROM users WHERE deleted_at IS NULL) as total_users,
        (SELECT COUNT(*) FROM consultants WHERE deleted_at IS NULL) as total_consultants,
        (SELECT COUNT(*) FROM clients WHERE deleted_at IS NULL) as total_clients,
        (SELECT COUNT(*) FROM contracts WHERE deleted_at IS NULL) as total_contracts,
        (SELECT COUNT(*) FROM invoices) as total_invoices,
        (SELECT COUNT(*) FROM automation_logs) as total_timesheets
    `);
    res.json(stats.rows[0]);
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Toggle reminder_enabled for a consultant
app.patch('/api/consultants/:id/reminder-toggle', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    const { reminder_enabled } = req.body;

    if (typeof reminder_enabled !== 'boolean') {
      return res.status(400).json({ error: 'reminder_enabled must be a boolean' });
    }

    const result = await pool.query(
      `UPDATE consultants SET reminder_enabled = $1 WHERE id = $2 AND company_id = $3 AND deleted_at IS NULL RETURNING id, reminder_enabled`,
      [reminder_enabled, id, req.companyId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Consultant not found' });
    }

    await logAudit(req.companyId, req.user.id, req.user.email,
      reminder_enabled ? 'REMINDER_ENABLED' : 'REMINDER_DISABLED', 'consultant', parseInt(id), {});

    res.json({ message: `Reminders ${reminder_enabled ? 'enabled' : 'disabled'}`, ...result.rows[0] });
  } catch (error) {
    console.error('Reminder toggle error:', error);
    res.status(500).json({ error: error.message });
  }
});


// ============================================================
// CREDIT NOTE ROUTES
// ============================================================

// Auto-migrate: add credit note columns if not present
(async () => {
  try {
    await pool.query(`
      ALTER TABLE invoices
        ADD COLUMN IF NOT EXISTS invoice_type_detail VARCHAR(20) DEFAULT 'standard',
        ADD COLUMN IF NOT EXISTS original_invoice_id INTEGER REFERENCES invoices(id) ON DELETE SET NULL
    `);
    // Drop positive_amounts constraint to allow negative values for credit notes
    await pool.query(`
      ALTER TABLE invoices DROP CONSTRAINT IF EXISTS positive_amounts
    `);
    console.log('✅ Credit note columns ready');
  } catch (err) {
    console.error('Migration warning (credit note columns):', err.message);
  }
})();

// Auto-migrate: PEPPOL columns
(async () => {
  try {
    await pool.query(`
      ALTER TABLE invoices
        ADD COLUMN IF NOT EXISTS peppol_status VARCHAR(50) DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS peppol_sent_at TIMESTAMPTZ DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS peppol_document_id VARCHAR(255) DEFAULT NULL
    `);
    await pool.query(`
      ALTER TABLE clients
        ADD COLUMN IF NOT EXISTS peppol_id VARCHAR(100) DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS country_code CHAR(2) DEFAULT NULL
    `);
    await pool.query(`
      ALTER TABLE companies
        ADD COLUMN IF NOT EXISTS peppol_enabled BOOLEAN DEFAULT false,
        ADD COLUMN IF NOT EXISTS peppol_provider VARCHAR(50) DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS peppol_api_key VARCHAR(500) DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS peppol_sender_id VARCHAR(100) DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS peppol_environment VARCHAR(20) DEFAULT 'mock',
        ADD COLUMN IF NOT EXISTS country_code CHAR(2) DEFAULT 'BE'
    `);
    console.log('✅ PEPPOL columns ready');
  } catch (err) {
    console.error('Migration warning (PEPPOL columns):', err.message);
  }
})();

// Auto-migrate: peppol_legal_entity_id column
(async () => {
  try {
    await pool.query(`
      ALTER TABLE companies
        ADD COLUMN IF NOT EXISTS peppol_legal_entity_id VARCHAR(50) DEFAULT NULL
    `);
    console.log('✅ peppol_legal_entity_id column ready');
  } catch (err) {
    console.error('Migration warning (peppol_legal_entity_id):', err.message);
  }
})();

// Auto-migrate: additional_files column for multiple attachments
(async () => {
  try {
    await pool.query(`
      ALTER TABLE automation_logs
        ADD COLUMN IF NOT EXISTS additional_files JSONB DEFAULT '[]'
    `);
    console.log('✅ additional_files column ready');
  } catch (err) {
    console.error('Migration warning (additional_files):', err.message);
  }
})();
(async () => {
  try {
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_invoices_company_id       ON invoices(company_id);
      CREATE INDEX IF NOT EXISTS idx_invoices_company_status   ON invoices(company_id, status);
      CREATE INDEX IF NOT EXISTS idx_invoices_company_date     ON invoices(company_id, invoice_date);
      CREATE INDEX IF NOT EXISTS idx_invoices_company_type     ON invoices(company_id, invoice_type);
      CREATE INDEX IF NOT EXISTS idx_invoices_contract_id      ON invoices(contract_id);
      CREATE INDEX IF NOT EXISTS idx_invoices_timesheet_id     ON invoices(timesheet_id);
      CREATE INDEX IF NOT EXISTS idx_invoices_original_id      ON invoices(original_invoice_id);
      CREATE INDEX IF NOT EXISTS idx_invoices_type_detail      ON invoices(company_id, invoice_type_detail);

      CREATE INDEX IF NOT EXISTS idx_timesheets_company_id     ON automation_logs(company_id);
      CREATE INDEX IF NOT EXISTS idx_timesheets_status         ON automation_logs(company_id, status);

      CREATE INDEX IF NOT EXISTS idx_contracts_company_id      ON contracts(company_id);
      CREATE INDEX IF NOT EXISTS idx_contracts_consultant_id   ON contracts(consultant_id);
      CREATE INDEX IF NOT EXISTS idx_contracts_client_id       ON contracts(client_id);

      CREATE INDEX IF NOT EXISTS idx_consultants_company_id    ON consultants(company_id);
      CREATE INDEX IF NOT EXISTS idx_clients_company_id        ON clients(company_id);

      CREATE INDEX IF NOT EXISTS idx_audit_logs_company_id     ON audit_logs(company_id);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at     ON audit_logs(company_id, created_at DESC);

      CREATE INDEX IF NOT EXISTS idx_users_company_id          ON users(company_id);
      CREATE INDEX IF NOT EXISTS idx_users_email               ON users(email);
    `);
    console.log('✅ Performance indexes ready');
  } catch (err) {
    console.error('Migration warning (indexes):', err.message);
  }
})();

// POST /api/invoices/:id/credit-note — create credit note for an invoice
app.post('/api/invoices/:id/credit-note', authenticateToken, checkCompanyAccess, async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;

    // Permission check
    if (req.user.role !== 'admin' && req.user.role !== 'super_admin') {
      const perms = req.user.permissions || {};
      if (!perms.can_create_credit_note) {
        return res.status(403).json({ error: 'You do not have permission to create credit notes.' });
      }
    }

    // Fetch original invoice with full join data
    const origResult = await client.query(`
      SELECT i.*,
             c.consultant_id, c.client_id, c.consultant_contract_id, c.client_contract_id,
             c.vat_enabled, c.vat_rate, c.consultant_vat_enabled, c.consultant_vat_rate
      FROM invoices i
      JOIN contracts c ON i.contract_id = c.id
      WHERE i.id = $1 AND i.company_id = $2
    `, [id, req.companyId]);

    if (origResult.rows.length === 0) {
      return res.status(404).json({ error: 'Invoice not found' });
    }

    const orig = origResult.rows[0];

    if (!['sent', 'paid', 'overdue'].includes(orig.status)) {
      return res.status(400).json({ error: 'Credit notes can only be created for Sent, Paid or Overdue invoices' });
    }

    if (orig.invoice_type_detail === 'credit_note') {
      return res.status(400).json({ error: 'Cannot create a credit note for a credit note' });
    }

    // Check if credit note already exists for this invoice
    const existingCN = await client.query(
      `SELECT id, invoice_number FROM invoices WHERE original_invoice_id = $1 AND invoice_type_detail = 'credit_note' AND company_id = $2`,
      [id, req.companyId]
    );
    if (existingCN.rows.length > 0) {
      return res.status(400).json({ error: `Credit note already exists: ${existingCN.rows[0].invoice_number}` });
    }

    await client.query('BEGIN');

    // Build CN number with separate sequential counter: CN-YYYY-XXXX
    const year = new Date().getFullYear();
    const cnCountResult = await client.query(
      `SELECT COUNT(*) as cnt FROM invoices 
       WHERE company_id = $1 AND invoice_type_detail = 'credit_note' 
       AND EXTRACT(YEAR FROM invoice_date) = $2`,
      [req.companyId, year]
    );
    const cnCount = parseInt(cnCountResult.rows[0].cnt, 10);
    const cnNumber = `CN-${year}-${String(cnCount + 1).padStart(4, '0')}`;

    // Insert credit note — negative amounts
    const cnResult = await client.query(`
      INSERT INTO invoices (
        company_id, contract_id, invoice_number, invoice_date,
        period_from, period_to, days_worked, daily_rate,
        subtotal, vat_rate, vat_enabled, vat_amount, total_amount,
        invoice_type, invoice_type_detail, original_invoice_id,
        status, timesheet_id
      ) VALUES ($1,$2,$3,CURRENT_DATE,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'credit_note',$14,'draft',$15)
      RETURNING *
    `, [
      req.companyId,
      orig.contract_id,
      cnNumber,
      orig.period_from,
      orig.period_to,
      orig.days_worked,
      orig.daily_rate,
      -(Math.abs(parseFloat(orig.subtotal))),
      orig.vat_rate,
      orig.vat_enabled,
      -(Math.abs(parseFloat(orig.vat_amount || 0))),
      -(Math.abs(parseFloat(orig.total_amount))),
      orig.invoice_type,
      id,
      orig.timesheet_id
    ]);

    const cn = cnResult.rows[0];

    // Fetch full CN with joins (names, company info) for frontend state update
    const cnFull = await client.query(`
      SELECT i.*,
             cons.first_name as consultant_first_name, cons.last_name as consultant_last_name,
             cons.company_name as consultant_company_name,
             cli.first_name as client_first_name, cli.last_name as client_last_name,
             cli.company_name as client_company_name
      FROM invoices i
      JOIN contracts c ON i.contract_id = c.id
      JOIN consultants cons ON c.consultant_id = cons.id
      JOIN clients cli ON c.client_id = cli.id
      WHERE i.id = $1
    `, [cn.id]);

    // Mark original invoice as credited
    await client.query(
      `UPDATE invoices SET invoice_type_detail = 'credited', status = 'credited', updated_at = NOW() WHERE id = $1`,
      [id]
    );

    // Release timesheet — allow re-generation
    if (orig.timesheet_id) {
      await client.query(
        `UPDATE automation_logs SET invoice_generated = false, processed = false WHERE id = $1`,
        [orig.timesheet_id]
      );
    }

    await client.query('COMMIT');

    await logAudit(req.companyId, req.user.id, req.user.email,
      'CREATE_CREDIT_NOTE', 'invoice', parseInt(id),
      { credit_note_number: cnNumber, original_invoice: orig.invoice_number });

    res.status(201).json({
      message: 'Credit note created successfully',
      creditNote: cnFull.rows[0],
      originalInvoiceId: id
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Credit note error:', error);
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

// ============================================================
// PEPPOL ROUTES
// ============================================================

// ── PEPPOL HELPER: Build Storecove-compatible payload ─────────────────────────
function buildStorecovePayload(invoice, companySettings) {
  // Parse client PEPPOL ID: "0208:0123456789" → scheme="0208", id="0123456789"
  const [clientScheme, ...clientIdParts] = (invoice.client_peppol_id || '').split(':');
  const clientPeppolId = clientIdParts.join(':');

  // Parse sender PEPPOL ID
  const [senderScheme, ...senderIdParts] = (companySettings.peppol_sender_id || '').split(':');
  const senderPeppolId = senderIdParts.join(':');

  const invoiceDate = invoice.invoice_date
    ? new Date(invoice.invoice_date).toISOString().split('T')[0]
    : new Date().toISOString().split('T')[0];

  const dueDate = invoice.due_date
    ? new Date(invoice.due_date).toISOString().split('T')[0]
    : null;

  const subtotal   = parseFloat(invoice.subtotal    || 0);
  const vatRate    = parseFloat(invoice.vat_rate     || 0);
  const vatAmount  = parseFloat(invoice.vat_amount   || 0);
  const total      = parseFloat(invoice.total_amount || 0);
  const daysWorked = parseFloat(invoice.days_worked  || 0);
  const dailyRate  = parseFloat(invoice.daily_rate   || 0);

  // Parse period for description
  const periodFrom = invoice.period_from
    ? new Date(invoice.period_from).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
    : '';
  const periodTo = invoice.period_to
    ? new Date(invoice.period_to).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
    : '';

  const consultantName = [invoice.consultant_first_name, invoice.consultant_last_name]
    .filter(Boolean).join(' ') || 'Consultant';

  const payload = {
    legalEntityId: companySettings.peppol_legal_entity_id ? parseInt(companySettings.peppol_legal_entity_id) : null,
    routing: {
      eidentifiers: [{ scheme: clientScheme || '0208', id: clientPeppolId || invoice.client_peppol_id }]
    },
    document: {
      document_type: 'invoice',
      invoice: {
        invoice_number:  invoice.invoice_number,
        invoice_date:    invoiceDate,
        currency:        'EUR',
        tax_system:      'tax_line_percentages',

        // ── Supplier (the agency) ─────────────────────────────────
        accounting_supplier_party: {
          party: {
            company_name: companySettings.name || '',
            address: {
              street1:  (companySettings.address || '').split('\n')[0] || '',
              city:     (companySettings.address || '').split('\n')[1] || '',
              country:  'BE'
            },
            contact: { email: companySettings.company_email || '' }
          },
          public_identifiers: senderPeppolId
            ? [{ scheme: senderScheme || '0208', id: senderPeppolId }]
            : [],
          tax_registration: companySettings.company_vat
            ? [{ tax_id: companySettings.company_vat.replace(/\s/g,''), id_type: 'VAT' }]
            : []
        },

        // ── Customer (the client) ─────────────────────────────────
        accounting_customer_party: {
          party: {
            company_name: invoice.client_company_name || '',
            address: {
              street1:  (invoice.client_address || '').split('\n')[0] || '',
              city:     (invoice.client_address || '').split('\n')[1] || '',
              country:  'BE'
            }
          },
          public_identifiers: [{ scheme: clientScheme || '0208', id: clientPeppolId || invoice.client_peppol_id }],
          tax_registration: invoice.client_vat
            ? [{ tax_id: invoice.client_vat.replace(/\s/g,''), id_type: 'VAT' }]
            : []
        },

        // ── Invoice line ──────────────────────────────────────────
        invoice_lines: [
          {
            line_id:     '1',
            description: `Consulting services — ${consultantName} (${periodFrom} – ${periodTo})`,
            quantity:     daysWorked,
            unit_code:   'DAY',
            unit_price:   dailyRate,
            amount_excluding_vat: subtotal,
            tax_percentage: vatRate
          }
        ],

        // ── VAT totals ────────────────────────────────────────────
        tax_subtotals: [
          {
            taxable_amount: subtotal,
            tax_amount:     vatAmount,
            tax_percentage: vatRate,
            tax_category:   invoice.vat_enabled ? 'S' : 'Z'  // S=standard, Z=zero-rated
          }
        ],

        // ── Totals ────────────────────────────────────────────────
        amount_including_vat: total,

        // ── Payment ───────────────────────────────────────────────
        ...(companySettings.bank_iban ? {
          payment_means_array: [{
            payment_means_code: '30',  // 30 = credit transfer
            financial_account: {
              id: companySettings.bank_iban.replace(/\s/g,''),
              name: companySettings.bank_name || '',
              ...(companySettings.bank_swift ? { financial_institution: { id: companySettings.bank_swift } } : {})
            }
          }]
        } : {}),

        ...(dueDate ? { payment_terms_note: `Due: ${dueDate}` } : {})
      }
    }
  };

  return payload;
}

// GET /api/peppol/lookup?id=0208:0462920226 — proxy to PEPPOL Directory (avoids CORS)
app.get('/api/peppol/lookup', authenticateToken, async (req, res) => {
  const { id } = req.query;
  if (!id) return res.status(400).json({ error: 'Missing id parameter' });
  try {
    // PEPPOL Directory requires format: iso6523-actorid-upis::SCHEME:ID
    const participant = `iso6523-actorid-upis::${id}`;
    const url = `https://directory.peppol.eu/search/1.0/json?participant=${encodeURIComponent(participant)}&resultCount=1`;
    const response = await fetch(url, { headers: { 'Accept': 'application/json' } });
    if (!response.ok) return res.status(502).json({ error: `Directory returned ${response.status}` });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(502).json({ error: `Directory unreachable: ${err.message}` });
  }
});

// POST /api/invoices/:id/send-peppol
app.post('/api/invoices/:id/send-peppol', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;

    // Fetch invoice + all related data needed for UBL
    const invoiceResult = await pool.query(
      `SELECT i.*,
              con.first_name  as consultant_first_name,
              con.last_name   as consultant_last_name,
              cli.company_name    as client_company_name,
              cli.company_address as client_address,
              cli.company_vat     as client_vat,
              cli.peppol_id       as client_peppol_id,
              co.name             as company_name,
              co.address          as company_address,
              co.company_vat,
              co.company_email,
              co.bank_iban,
              co.bank_name,
              co.bank_swift,
              co.peppol_enabled,
              co.peppol_provider,
              co.peppol_api_key,
              co.peppol_sender_id,
              co.peppol_environment,
              co.peppol_legal_entity_id
       FROM invoices i
       LEFT JOIN contracts c   ON i.contract_id = c.id
       LEFT JOIN consultants con ON c.consultant_id = con.id
       LEFT JOIN clients cli   ON c.client_id = cli.id
       LEFT JOIN companies co  ON i.company_id = co.id
       WHERE i.id = $1 AND i.company_id = $2`,
      [id, req.companyId]
    );

    if (invoiceResult.rows.length === 0) {
      return res.status(404).json({ error: 'Invoice not found' });
    }

    const invoice = invoiceResult.rows[0];

    if (!invoice.peppol_enabled) {
      return res.status(400).json({ error: 'PEPPOL is not enabled for this company. Enable it in Settings first.' });
    }
    if (invoice.invoice_type !== 'client') {
      return res.status(400).json({ error: 'Only client invoices can be sent via PEPPOL' });
    }
    if (!['sent', 'paid', 'draft'].includes(invoice.status)) {
      return res.status(400).json({ error: 'Invoice must be in draft, sent, or paid status' });
    }
    if (!invoice.client_peppol_id) {
      return res.status(400).json({
        error: 'Client has no PEPPOL ID. Edit the client profile first.',
        requiresPeppolId: true
      });
    }

    const env = (invoice.peppol_environment || 'mock').toLowerCase().trim();

    // ── MOCK MODE ──────────────────────────────────────────────────────────────
    if (env === 'mock') {
      await new Promise(r => setTimeout(r, 1500));
      if (Math.random() < 0.05) {
        await pool.query(`UPDATE invoices SET peppol_status='failed', peppol_sent_at=NOW() WHERE id=$1`, [id]);
        return res.status(502).json({ error: 'PEPPOL delivery failed (mock simulation)' });
      }
      const mockDocId = `MOCK-${Date.now()}-${Math.random().toString(36).substr(2,8).toUpperCase()}`;
      await pool.query(
        `UPDATE invoices SET peppol_status='delivered', peppol_sent_at=NOW(), peppol_document_id=$1 WHERE id=$2`,
        [mockDocId, id]
      );
      await logAudit(req.companyId, req.user.id, req.user.email, 'PEPPOL_SENT', 'invoice', parseInt(id),
        { invoice_number: invoice.invoice_number, mock: true, document_id: mockDocId });
      return res.json({ success: true, mock: true, message: `Invoice ${invoice.invoice_number} delivered via PEPPOL (mock)`, document_id: mockDocId });
    }

    // ── SANDBOX / PRODUCTION MODE (Storecove) ──────────────────────────────────
    if (env === 'sandbox' || env === 'production') {
      if (!invoice.peppol_api_key) {
        return res.status(400).json({ error: 'No API key configured. Add it in Settings → PEPPOL.' });
      }
      if (!invoice.peppol_sender_id) {
        return res.status(400).json({ error: 'No Sender PEPPOL ID configured. Add it in Settings → PEPPOL.' });
      }

      const provider = invoice.peppol_provider || 'storecove';

      if (provider === 'storecove') {
        const baseUrl = 'https://api.storecove.com/api/v2';

        // Build payload
        const companySettings = {
          name:          invoice.company_name,
          address:       invoice.company_address,
          company_vat:   invoice.company_vat,
          company_email: invoice.company_email,
          bank_iban:     invoice.bank_iban,
          bank_name:     invoice.bank_name,
          bank_swift:    invoice.bank_swift,
          peppol_sender_id: invoice.peppol_sender_id,
          peppol_legal_entity_id: invoice.peppol_legal_entity_id
        };
        const payload = buildStorecovePayload(invoice, companySettings);

        // In sandbox mode — add test flag
        if (env === 'sandbox') {
          payload.test = true;
        }

        console.log('PEPPOL Storecove payload:', JSON.stringify(payload, null, 2));

        const response = await fetch(`${baseUrl}/document_submissions`, {
          method:  'POST',
          headers: {
            'Authorization': `Bearer ${invoice.peppol_api_key}`,
            'Content-Type':  'application/json',
            'Accept':        'application/json'
          },
          body: JSON.stringify(payload)
        });

        const responseText = await response.text();
        let responseData = {};
        try { responseData = JSON.parse(responseText); } catch(e) { responseData = { raw: responseText }; }

        console.log('Storecove response:', response.status, responseText);

        if (!response.ok) {
          await pool.query(
            `UPDATE invoices SET peppol_status='failed', peppol_sent_at=NOW() WHERE id=$1`, [id]
          );
          await logAudit(req.companyId, req.user.id, req.user.email, 'PEPPOL_FAILED', 'invoice', parseInt(id),
            { invoice_number: invoice.invoice_number, error: responseData, env });
          return res.status(response.status).json({
            error: responseData.error || responseData.message || 'Storecove API error',
            details: responseData,
            raw: responseText
          });
        }

        const documentId = responseData.guid || responseData.id || `SC-${Date.now()}`;
        await pool.query(
          `UPDATE invoices SET peppol_status='pending', peppol_sent_at=NOW(), peppol_document_id=$1 WHERE id=$2`,
          [documentId, id]
        );
        await logAudit(req.companyId, req.user.id, req.user.email, 'PEPPOL_SENT', 'invoice', parseInt(id),
          { invoice_number: invoice.invoice_number, document_id: documentId, env, provider });

        return res.json({
          success:     true,
          mock:        false,
          env,
          provider,
          message:     `Invoice ${invoice.invoice_number} submitted to PEPPOL via Storecove`,
          document_id: documentId,
          storecove:   responseData
        });

      } else {
        // Other providers (Billit, Advalvas, etc.) — stub
        return res.status(501).json({
          error: `Provider '${provider}' not yet implemented. Currently supported: storecove`
        });
      }
    }

    return res.status(400).json({ error: `Unknown PEPPOL environment: ${env}` });

  } catch (error) {
    console.error('PEPPOL send error:', error);
    res.status(500).json({ error: error.message });
  }
});

// PATCH /api/invoices/:id/peppol-status — manual status override (for testing)
app.patch('/api/invoices/:id/peppol-status', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body; // pending | delivered | failed | null
    const allowed = ['pending', 'delivered', 'failed', null];
    if (!allowed.includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    const result = await pool.query(
      `UPDATE invoices SET peppol_status = $1 WHERE id = $2 AND company_id = $3 RETURNING *`,
      [status, id, req.companyId]
    );
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/invoices/:id/peppol-xml — generate UBL 2.1 XML for validation
app.get('/api/invoices/:id/peppol-xml', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;

    const invoiceResult = await pool.query(
      `SELECT i.*,
              con.first_name  as consultant_first_name,
              con.last_name   as consultant_last_name,
              cli.company_name    as client_company_name,
              cli.company_address as client_address,
              cli.company_vat     as client_vat,
              cli.peppol_id       as client_peppol_id,
              cli.country_code    as client_country_code,
              co.name             as company_name,
              co.address          as company_address,
              co.company_vat,
              co.company_email,
              co.bank_iban,
              co.bank_name,
              co.bank_swift,
              co.peppol_sender_id,
              co.country_code as company_country_code
       FROM invoices i
       LEFT JOIN contracts c   ON i.contract_id = c.id
       LEFT JOIN consultants con ON c.consultant_id = con.id
       LEFT JOIN clients cli   ON c.client_id = cli.id
       LEFT JOIN companies co  ON i.company_id = co.id
       WHERE i.id = $1 AND i.company_id = $2`,
      [id, req.companyId]
    );

    if (invoiceResult.rows.length === 0) {
      return res.status(404).json({ error: 'Invoice not found' });
    }

    const inv = invoiceResult.rows[0];

    const invoiceDate = inv.invoice_date
      ? new Date(inv.invoice_date).toISOString().split('T')[0]
      : new Date().toISOString().split('T')[0];
    const dueDate = inv.due_date
      ? new Date(inv.due_date).toISOString().split('T')[0]
      : new Date(Date.now() + 30*24*60*60*1000).toISOString().split('T')[0];

    const subtotal  = parseFloat(inv.subtotal    || 0).toFixed(2);
    const vatRate   = parseFloat(inv.vat_rate     || 0).toFixed(2);
    const vatAmount = parseFloat(inv.vat_amount   || 0).toFixed(2);
    const total     = parseFloat(inv.total_amount || 0).toFixed(2);
    const days      = parseFloat(inv.days_worked  || 0).toFixed(2);
    const rate      = parseFloat(inv.daily_rate   || 0).toFixed(2);

    const periodFrom = inv.period_from
      ? new Date(inv.period_from).toLocaleDateString('en-GB', { day:'2-digit', month:'short', year:'numeric' }) : '';
    const periodTo = inv.period_to
      ? new Date(inv.period_to).toLocaleDateString('en-GB', { day:'2-digit', month:'short', year:'numeric' }) : '';
    const consultantName = [inv.consultant_first_name, inv.consultant_last_name].filter(Boolean).join(' ') || 'Consultant';

    const [senderScheme, ...senderRest] = (inv.peppol_sender_id || '0208:UNKNOWN').split(':');
    const senderId = senderRest.join(':') || 'UNKNOWN';
    const [clientScheme, ...clientRest] = (inv.client_peppol_id || '0208:UNKNOWN').split(':');
    const clientId = clientRest.join(':') || 'UNKNOWN';

    const isCreditNote = inv.invoice_type_detail === 'credit_note';
    const invoiceTypeCode = isCreditNote ? '381' : '380'; // 380=Invoice, 381=CreditNote

    const taxCategory = inv.vat_enabled ? 'S' : 'Z';

    const supplierLines = (inv.company_address || '').split('\n');
    const clientLines   = (inv.client_address  || '').split('\n');

    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">

  <cbc:CustomizationID>urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0</cbc:CustomizationID>
  <cbc:ProfileID>urn:fdc:peppol.eu:2017:poacc:billing:01:1.0</cbc:ProfileID>
  <cbc:ID>${inv.invoice_number}</cbc:ID>
  <cbc:IssueDate>${invoiceDate}</cbc:IssueDate>
  <cbc:DueDate>${dueDate}</cbc:DueDate>
  <cbc:InvoiceTypeCode>${invoiceTypeCode}</cbc:InvoiceTypeCode>
  <cbc:DocumentCurrencyCode>EUR</cbc:DocumentCurrencyCode>
  <cbc:BuyerReference>${inv.invoice_number}</cbc:BuyerReference>

  <!-- Supplier -->
  <cac:AccountingSupplierParty>
    <cac:Party>
      <cbc:EndpointID schemeID="${senderScheme}">${senderId}</cbc:EndpointID>
      <cac:PartyName><cbc:Name>${inv.company_name || ''}</cbc:Name></cac:PartyName>
      <cac:PostalAddress>
        ${supplierLines[0] ? `<cbc:StreetName>${supplierLines[0]}</cbc:StreetName>` : ''}
        ${supplierLines[1] ? `<cbc:CityName>${supplierLines[1]}</cbc:CityName>` : ''}
        <cac:Country><cbc:IdentificationCode>${inv.company_country_code || 'BE'}</cbc:IdentificationCode></cac:Country>
      </cac:PostalAddress>
      <cac:PartyTaxScheme>
        <cbc:CompanyID>${(inv.company_vat || '').replace(/\s/g,'')}</cbc:CompanyID>
        <cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme>
      </cac:PartyTaxScheme>
      <cac:PartyLegalEntity>
        <cbc:RegistrationName>${inv.company_name || ''}</cbc:RegistrationName>
        <cbc:CompanyID>${(inv.company_vat || '').replace(/\s/g,'')}</cbc:CompanyID>
      </cac:PartyLegalEntity>
      <cac:Contact><cbc:ElectronicMail>${inv.company_email || ''}</cbc:ElectronicMail></cac:Contact>
    </cac:Party>
  </cac:AccountingSupplierParty>

  <!-- Customer -->
  <cac:AccountingCustomerParty>
    <cac:Party>
      <cbc:EndpointID schemeID="${clientScheme}">${clientId}</cbc:EndpointID>
      <cac:PartyName><cbc:Name>${inv.client_company_name || ''}</cbc:Name></cac:PartyName>
      <cac:PostalAddress>
        ${clientLines[0] ? `<cbc:StreetName>${clientLines[0]}</cbc:StreetName>` : ''}
        ${clientLines[1] ? `<cbc:CityName>${clientLines[1]}</cbc:CityName>` : ''}
        <cac:Country><cbc:IdentificationCode>${inv.client_country_code || 'BE'}</cbc:IdentificationCode></cac:Country>
      </cac:PostalAddress>
      <cac:PartyTaxScheme>
        <cbc:CompanyID>${(inv.client_vat || '').replace(/\s/g,'')}</cbc:CompanyID>
        <cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme>
      </cac:PartyTaxScheme>
      <cac:PartyLegalEntity>
        <cbc:RegistrationName>${inv.client_company_name || ''}</cbc:RegistrationName>
        <cbc:CompanyID>${(inv.client_vat || '').replace(/\s/g,'')}</cbc:CompanyID>
      </cac:PartyLegalEntity>
    </cac:Party>
  </cac:AccountingCustomerParty>

  <!-- Payment means -->
  ${inv.bank_iban ? `<cac:PaymentMeans>
    <cbc:PaymentMeansCode>30</cbc:PaymentMeansCode>
    <cbc:PaymentID>${inv.invoice_number}</cbc:PaymentID>
    <cac:PayeeFinancialAccount>
      <cbc:ID>${(inv.bank_iban || '').replace(/\s/g,'')}</cbc:ID>
      <cbc:Name>${inv.bank_name || ''}</cbc:Name>
      ${inv.bank_swift ? `<cac:FinancialInstitutionBranch>
        <cbc:ID>${inv.bank_swift}</cbc:ID>
      </cac:FinancialInstitutionBranch>` : ''}
    </cac:PayeeFinancialAccount>
  </cac:PaymentMeans>` : ''}

  <!-- VAT totals -->
  <cac:TaxTotal>
    <cbc:TaxAmount currencyID="EUR">${vatAmount}</cbc:TaxAmount>
    <cac:TaxSubtotal>
      <cbc:TaxableAmount currencyID="EUR">${subtotal}</cbc:TaxableAmount>
      <cbc:TaxAmount currencyID="EUR">${vatAmount}</cbc:TaxAmount>
      <cac:TaxCategory>
        <cbc:ID>${taxCategory}</cbc:ID>
        <cbc:Percent>${vatRate}</cbc:Percent>
        <cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme>
      </cac:TaxCategory>
    </cac:TaxSubtotal>
  </cac:TaxTotal>

  <!-- Monetary totals -->
  <cac:LegalMonetaryTotal>
    <cbc:LineExtensionAmount currencyID="EUR">${subtotal}</cbc:LineExtensionAmount>
    <cbc:TaxExclusiveAmount currencyID="EUR">${subtotal}</cbc:TaxExclusiveAmount>
    <cbc:TaxInclusiveAmount currencyID="EUR">${total}</cbc:TaxInclusiveAmount>
    <cbc:PayableAmount currencyID="EUR">${total}</cbc:PayableAmount>
  </cac:LegalMonetaryTotal>

  <!-- Invoice line -->
  <cac:InvoiceLine>
    <cbc:ID>1</cbc:ID>
    <cbc:InvoicedQuantity unitCode="DAY">${days}</cbc:InvoicedQuantity>
    <cbc:LineExtensionAmount currencyID="EUR">${subtotal}</cbc:LineExtensionAmount>
    <cac:Item>
      <cbc:Description>Consulting services — ${consultantName} (${periodFrom} – ${periodTo})</cbc:Description>
      <cbc:Name>Consulting services</cbc:Name>
      <cac:ClassifiedTaxCategory>
        <cbc:ID>${taxCategory}</cbc:ID>
        <cbc:Percent>${vatRate}</cbc:Percent>
        <cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme>
      </cac:ClassifiedTaxCategory>
    </cac:Item>
    <cac:Price>
      <cbc:PriceAmount currencyID="EUR">${rate}</cbc:PriceAmount>
    </cac:Price>
  </cac:InvoiceLine>

</Invoice>`;

    res.setHeader('Content-Type', 'application/xml');
    res.setHeader('Content-Disposition', `attachment; filename="${inv.invoice_number}-peppol${isCreditNote ? '-creditnote' : ''}.xml"`);
    res.send(xml);

  } catch (error) {
    console.error('PEPPOL XML generation error:', error);
    res.status(500).json({ error: error.message });
  }
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Invoice Generator API running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
});

module.exports = app;
// ============================================
// AUDIT LOGS ENDPOINT
// ============================================
app.get('/api/audit-logs', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const { limit = 100, offset = 0, entity_type, action } = req.query;
    let query = `
      SELECT al.*, u.first_name, u.last_name
      FROM audit_logs al
      LEFT JOIN users u ON al.user_id = u.id
      WHERE al.company_id = $1
    `;
    const params = [req.companyId];
    let paramIdx = 2;

    if (entity_type) {
      query += ` AND al.entity_type = $${paramIdx++}`;
      params.push(entity_type);
    }
    if (action) {
      query += ` AND al.action = $${paramIdx++}`;
      params.push(action);
    }

    query += ` ORDER BY al.created_at DESC LIMIT $${paramIdx++} OFFSET $${paramIdx}`;
    params.push(parseInt(limit), parseInt(offset));

    const result = await pool.query(query, params);
    const countResult = await pool.query(
      `SELECT COUNT(*) FROM audit_logs WHERE company_id = $1`,
      [req.companyId]
    );

    res.json({ logs: result.rows, total: parseInt(countResult.rows[0].count) });
  } catch (error) {
    console.error('Get audit logs error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// TIMESHEET REMINDERS
// ============================================

// Core reminder logic - reused by both manual trigger and cron
const sendPendingReminders = async (companyId = null) => {
  const results = { sent: 0, skipped: 0, errors: [] };

  try {
    // Get companies to process
    const companiesQuery = companyId
      ? 'SELECT * FROM companies WHERE id = $1'
      : 'SELECT * FROM companies';
    const companiesResult = await pool.query(companiesQuery, companyId ? [companyId] : []);

    for (const company of companiesResult.rows) {
      if (!hasSMTP(company)) { results.skipped++; continue; }

      const deadlineDay = company.timesheet_deadline_day || 15;
      const now = new Date();
      const currentDay = now.getDate();

      // Determine which month we're checking
      const checkingDate = currentDay <= deadlineDay
        ? new Date(now.getFullYear(), now.getMonth() - 1, 1)
        : new Date(now.getFullYear(), now.getMonth(), 1);

      const checkingMonth = checkingDate.toLocaleDateString('en-US', { month: 'long' });
      const checkingYear = checkingDate.getFullYear();
      const firstDay = new Date(checkingYear, checkingDate.getMonth(), 1).toISOString().split('T')[0];
      const lastDay = new Date(checkingYear, checkingDate.getMonth() + 1, 0).toISOString().split('T')[0];

      // Get active contracts for this period (only consultants with reminders enabled)
      const contractsResult = await pool.query(`
        SELECT c.id as contract_id, c.from_date, c.to_date,
               cons.id as consultant_id, cons.email as consultant_email,
               cons.first_name, cons.last_name
        FROM contracts c
        JOIN consultants cons ON c.consultant_id = cons.id
        WHERE c.company_id = $1
          AND c.from_date <= $2
          AND c.to_date >= $3
          AND c.deleted_at IS NULL
          AND cons.deleted_at IS NULL
          AND cons.reminder_enabled = TRUE
          AND (c.reminder_sent_at IS NULL OR c.reminder_sent_at < $4)
      `, [company.id, lastDay, firstDay, `${checkingYear}-${checkingDate.getMonth() + 1}-01`]);

      for (const contract of contractsResult.rows) {
        // Check if timesheet already submitted for this month
        const tsResult = await pool.query(`
          SELECT id FROM automation_logs
          WHERE company_id = $1
            AND LOWER(sender_email) = LOWER($2)
            AND LOWER(month) = LOWER($3)
            AND invoice_generated = false
          LIMIT 1
        `, [company.id, contract.consultant_email, checkingMonth]);

        if (tsResult.rows.length > 0) {
          results.skipped++;
          continue; // Already submitted
        }

        try {
          await sendTimesheetReminder(
            contract.consultant_email,
            `${contract.first_name} ${contract.last_name}`,
            checkingMonth,
            deadlineDay,
            company
          );
          // Mark reminder sent on contract
          await pool.query(
            'UPDATE contracts SET reminder_sent_at = NOW() WHERE id = $1',
            [contract.contract_id]
          );
          console.log(`📧 Reminder sent to ${contract.consultant_email} for ${checkingMonth}`);
          results.sent++;
        } catch (emailErr) {
          console.error(`Reminder failed for ${contract.consultant_email}:`, emailErr.message);
          results.errors.push({ consultant: contract.consultant_email, error: emailErr.message });
        }
      }
    }
  } catch (err) {
    console.error('sendPendingReminders error:', err);
    results.errors.push({ error: err.message });
  }

  return results;
};

// Manual trigger endpoint (admin only)
app.post('/api/timesheets/send-reminders', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const results = await sendPendingReminders(req.companyId);
    await logAudit(req.companyId, req.user.id, req.user.email,
      'SEND_REMINDERS', 'timesheet', null, results);
    res.json({ message: 'Reminders processed', ...results });
  } catch (error) {
    console.error('Send reminders error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// CRON: Send reminders daily at 09:00
// Runs 5 days before deadline and day before deadline
// ============================================
cron.schedule('0 9 * * *', async () => {
  console.log('🕐 Cron: checking timesheet reminders...');
  try {
    const companiesResult = await pool.query('SELECT id, timesheet_deadline_day FROM companies');
    
    for (const company of companiesResult.rows) {
      const deadlineDay = company.timesheet_deadline_day || 15;
      const today = new Date().getDate();

      // Only send reminder the day BEFORE the deadline
      if (today === deadlineDay - 1) {
        console.log(`📅 Tomorrow is deadline day ${deadlineDay} for company ${company.id} — sending reminders`);
        const results = await sendPendingReminders(company.id);
        console.log(`📧 Reminders for company ${company.id}:`, results);
      }
    }
  } catch (err) {
    console.error('Cron reminder error:', err);
  }
});
