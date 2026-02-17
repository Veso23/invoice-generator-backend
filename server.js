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
    can_delete_timesheets: true
  },
  operator: {
    can_view_dashboard: false,
    can_view_contracts: false,
    can_view_consultants: true,
    can_view_clients: true,
    can_view_timesheets: true,
    can_view_invoices: true,
    can_manage_users: false,
    can_delete_timesheets: false
  }
};


app.use(compression());
app.use(morgan('combined'));

// CORS configuration - MUST BE BEFORE OTHER MIDDLEWARE
app.use(cors({
  origin: [
    'https://invoice-generator-frontend-inky.vercel.app',
    'http://localhost:3000'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Impersonate-Company']
}));

// Handle preflight requests explicitly
app.options('*', cors());

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

// Database connection with Supabase
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  },
  // Ensure UTF-8 encoding for Cyrillic and other characters
  client_encoding: 'UTF8'
});

// Set encoding on each new connection
pool.on('connect', (client) => {
  client.query('SET client_encoding = UTF8');
  console.log('✅ Connected to Supabase database (UTF-8)');
});

pool.on('error', (err) => {
  console.error('❌ Database connection error:', err);
});

const nodemailer = require('nodemailer');

// Email Service
const sendInvoiceEmail = async (invoice, companySettings, recipientEmail, recipientName) => {
  // Check if SMTP is configured
  if (!companySettings.smtp_host || !companySettings.smtp_username || !companySettings.smtp_password) {
    throw new Error('Email settings not configured. Please configure SMTP in Company Settings.');
  }

// Create transporter with timeout and TLS options
  const smtpPort = parseInt(companySettings.smtp_port) || 587;
  const isSecure = smtpPort === 465; // Port 465 = SSL, 587 = STARTTLS
  
  console.log('📧 SMTP Config:', {
    host: companySettings.smtp_host,
    port: smtpPort,
    secure: isSecure,
    user: companySettings.smtp_username
  });
  
  const transporter = nodemailer.createTransport({
    host: companySettings.smtp_host,
    port: smtpPort,
    secure: isSecure,
    auth: {
      user: companySettings.smtp_username,
      pass: companySettings.smtp_password
    },
    connectionTimeout: 10000, // 10 seconds
    greetingTimeout: 10000,
    socketTimeout: 15000,
    tls: {
      rejectUnauthorized: false // Allow self-signed certificates (common on cPanel)
    }
  });

  // Verify connection
  try {
    await transporter.verify();
  } catch (error) {
    console.error('SMTP verification failed:', error);
    throw new Error('Failed to connect to email server. Please check your SMTP settings.');
  }

  // Email content
  const emailSubject = `Invoice ${invoice.invoice_number} - ${companySettings.name}`;
  
  const emailHTML = `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #2563eb; color: white; padding: 20px; text-align: center; }
        .content { background-color: #f9fafb; padding: 30px; border: 1px solid #e5e7eb; }
        .invoice-details { background-color: white; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .footer { text-align: center; padding: 20px; font-size: 12px; color: #6b7280; }
        .button { display: inline-block; background-color: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>${companySettings.name}</h1>
        </div>
        <div class="content">
          <p>Dear ${recipientName},</p>
          
          <p>Please find your invoice attached to this email.</p>
          
          <div class="invoice-details">
            <strong>Invoice Number:</strong> ${invoice.invoice_number}<br>
            <strong>Date:</strong> ${new Date(invoice.invoice_date).toLocaleDateString('en-GB')}<br>
            <strong>Amount:</strong> €${parseFloat(invoice.total_amount).toFixed(2)}<br>
            <strong>Status:</strong> ${invoice.status}
          </div>
          
          ${invoice.pdf_url ? `<a href="${invoice.pdf_url}" class="button">Download Invoice PDF</a>` : ''}
          
          <p>If you have any questions about this invoice, please don't hesitate to contact us.</p>
          
          <p>Best regards,<br>
          ${companySettings.representative_name || companySettings.name}</p>
        </div>
        <div class="footer">
          <p>${companySettings.address || ''}</p>
          <p>${companySettings.company_email || ''}</p>
        </div>
      </div>
    </body>
    </html>
  `;

  // Send email
  const info = await transporter.sendMail({
    from: `"${companySettings.smtp_from_name || companySettings.name}" <${companySettings.smtp_from_email || companySettings.smtp_username}>`,
    to: recipientEmail,
    subject: emailSubject,
    html: emailHTML,
    attachments: invoice.pdf_url ? [{
      filename: `Invoice-${invoice.invoice_number}.pdf`,
      path: invoice.pdf_url
    }] : []
  });

  return info;
};


// Authentication middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret');
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
  // Super admin can override company_id via header
  const impersonateHeader = req.headers['x-impersonate-company'];
  
  if (req.user.role === 'superadmin' && impersonateHeader) {
    req.companyId = parseInt(impersonateHeader);
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
        process.env.JWT_SECRET || 'fallback-secret',
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
      process.env.JWT_SECRET || 'fallback-secret',
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
    const result = await pool.query(
      'SELECT * FROM consultants WHERE company_id = $1 AND deleted_at IS NULL ORDER BY created_at DESC',
      [req.companyId]
    );
    res.json(result.rows);
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
          ON CONFLICT (email, company_id) DO NOTHING
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
    const result = await pool.query(
      'SELECT * FROM clients WHERE company_id = $1 AND deleted_at IS NULL ORDER BY created_at DESC',
      [req.companyId]
    );
    res.json(result.rows);
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
          ON CONFLICT (email, company_id) DO NOTHING
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
      phone, email, iban, swift, clientContractId 
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
           company_vat = $5, phone = $6, email = $7, iban = $8, swift = $9, client_contract_id = $10
       WHERE id = $11 AND company_id = $12 AND deleted_at IS NULL RETURNING *`,
      [firstName, lastName, companyName, companyAddress, companyVat, phone, email, iban, swift, clientContractId, id, req.companyId]
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
    const result = await pool.query(`
      SELECT 
        c.id,
        c.uuid,
        c.consultant_id,
        c.client_id,
        c.contract_number,
        c.from_date,
        c.to_date,
        c.purchase_price,
        c.sell_price,
        c.currency,
        c.status,
        c.notes,
        c.vat_enabled,
        c.vat_rate,
        c.consultant_vat_enabled,
        c.consultant_vat_rate,
        c.company_id,
        c.created_at,
        c.updated_at,
        cons.consultant_contract_id,
        cli.client_contract_id,
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
      WHERE c.company_id = $1 AND c.deleted_at IS NULL
      ORDER BY c.created_at DESC
    `, [req.companyId]);

    res.json(result.rows);
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
             CASE WHEN c.id IS NOT NULL THEN true ELSE false END as consultant_matched
      FROM automation_logs al
      LEFT JOIN consultants c ON al.sender_email = c.email AND c.company_id = $1 AND c.deleted_at IS NULL
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
    
    // ✅ Check if contract is already selected on timesheet
    if (timesheet.contract_id) {
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
    } else {
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
    
    // ✅ Generate invoice numbers with SEPARATE sequences
    // Lock the invoices table for this company to prevent race conditions
    await client.query(
      'SELECT id FROM invoices WHERE company_id = $1 FOR UPDATE',
      [req.companyId]
    );

    // Get consultant full name for invoice numbering (remove spaces and special chars)
    const consultantFullName = (consultant.first_name + consultant.last_name)
      .replace(/[^a-zA-Z0-9]/g, '');
    
    // Count CLIENT invoices only (one sequence for all client invoices)
    const clientInvoiceCountResult = await client.query(
      `SELECT COUNT(*) FROM invoices WHERE company_id = $1 AND invoice_type = 'client'`,
      [req.companyId]
    );
    const clientInvoiceCount = parseInt(clientInvoiceCountResult.rows[0].count);
    const clientInvoiceNumber = `INV-${year}-${String(clientInvoiceCount + 1).padStart(4, '0')}`;
    
    // Count CONSULTANT invoices for THIS consultant only (separate sequence per consultant)
    const consultantInvoiceCountResult = await client.query(
      `SELECT COUNT(*) FROM invoices i
       JOIN contracts c ON i.contract_id = c.id
       WHERE i.company_id = $1 AND i.invoice_type = 'consultant' AND c.consultant_id = $2`,
      [req.companyId, consultant.id]
    );
    const consultantInvoiceCount = parseInt(consultantInvoiceCountResult.rows[0].count);
    const consultantInvoiceNumber = `INV-${year}-${String(consultantInvoiceCount + 1).padStart(4, '0')}-${consultantFullName}`;
    
    // CALCULATE CONSULTANT INVOICE
    const consultantDailyRate = parseFloat(contract.purchase_price);
    const consultantSubtotal = Math.round(consultantDailyRate * daysWorked * 100) / 100;
    
    const consultantVatRate = contract.consultant_vat_enabled && contract.consultant_vat_rate 
      ? parseFloat(contract.consultant_vat_rate) 
      : 0;
    
    const consultantVatAmount = Math.round(consultantSubtotal * (consultantVatRate / 100) * 100) / 100;
    const consultantTotal = Math.round((consultantSubtotal + consultantVatAmount) * 100) / 100;
    
    console.log('Consultant invoice:', {
      contract: contract.contract_number,
      dailyRate: consultantDailyRate,
      daysWorked,
      subtotal: consultantSubtotal,
      vatEnabled: contract.consultant_vat_enabled,
      vatRate: consultantVatRate,
      vatAmount: consultantVatAmount,
      total: consultantTotal
    });
    
    const consultantInvoiceResult = await client.query(
      `INSERT INTO invoices (
        company_id, contract_id, invoice_number, invoice_date, 
        period_from, period_to, days_worked, daily_rate, 
        subtotal, vat_rate, vat_enabled, vat_amount, total_amount, 
        invoice_type, status, timesheet_id
      ) VALUES ($1, $2, $3, CURRENT_DATE, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
      RETURNING *`,
      [
        req.companyId,
        contract.id,
        consultantInvoiceNumber,
        periodFrom,
        periodTo,
        daysWorked,
        consultantDailyRate,
        consultantSubtotal,
        consultantVatRate,
        contract.consultant_vat_enabled || false,
        consultantVatAmount,
        consultantTotal,
        'consultant',
        'draft',
        id
      ]
    );
    
    // CALCULATE CLIENT INVOICE
    const clientDailyRate = parseFloat(contract.sell_price);
    const clientSubtotal = Math.round(clientDailyRate * daysWorked * 100) / 100;
    
    const clientVatRate = contract.vat_enabled && contract.vat_rate 
      ? parseFloat(contract.vat_rate) 
      : 0;
    
    const clientVatAmount = Math.round(clientSubtotal * (clientVatRate / 100) * 100) / 100;
    const clientTotal = Math.round((clientSubtotal + clientVatAmount) * 100) / 100;
    
    console.log('Client invoice:', {
      contract: contract.contract_number,
      dailyRate: clientDailyRate,
      daysWorked,
      subtotal: clientSubtotal,
      vatEnabled: contract.vat_enabled,
      vatRate: clientVatRate,
      vatAmount: clientVatAmount,
      total: clientTotal
    });
    
    const clientInvoiceResult = await client.query(
      `INSERT INTO invoices (
        company_id, contract_id, invoice_number, invoice_date, 
        period_from, period_to, days_worked, daily_rate, 
        subtotal, vat_rate, vat_enabled, vat_amount, total_amount, 
        invoice_type, status, timesheet_id
      ) VALUES ($1, $2, $3, CURRENT_DATE, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
      RETURNING *`,
      [
        req.companyId,
        contract.id,
        clientInvoiceNumber,
        periodFrom,
        periodTo,
        daysWorked,
        clientDailyRate,
        clientSubtotal,
        clientVatRate,
        contract.vat_enabled || false,
        clientVatAmount,
        clientTotal,
        'client',
        'draft',
        id
      ]
    );
    
    // Mark timesheet as invoiced
    await client.query(
      'UPDATE automation_logs SET invoice_generated = true WHERE id = $1',
      [id]
    );
    
    // Commit transaction
    await client.query('COMMIT');
    
    console.log('✅ SUCCESS: Invoices created for contract:', contract.contract_number, 
                'timesheet_id:', id, 'daysWorked:', daysWorked, 'period:', `${monthName} ${year}`);
    
    res.json({ 
      message: 'Invoices generated successfully',
      consultantInvoice: consultantInvoiceResult.rows[0],
      clientInvoice: clientInvoiceResult.rows[0],
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


// Get all invoices
app.get('/api/invoices', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const result = await pool.query(`
SELECT i.*, 
       c.consultant_contract_id, 
       c.client_contract_id,
       cons.first_name as consultant_first_name,
       cons.last_name as consultant_last_name,
       cons.company_name as consultant_company_name,
       cli.first_name as client_first_name,
       cli.last_name as client_last_name,
       cli.company_name as client_company_name
FROM invoices i
JOIN contracts c ON i.contract_id = c.id
JOIN consultants cons ON c.consultant_id = cons.id
JOIN clients cli ON c.client_id = cli.id
WHERE i.company_id = $1
ORDER BY i.created_at DESC
    `, [req.companyId]);

    res.json(result.rows);
  } catch (error) {
    console.error('Get invoices error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// N8N Integration - Webhook endpoint
app.post('/api/n8n/automation-data', async (req, res) => {
  try {
    const {
      timestamp, senderEmail, recipientEmail, personName, month,
      emailHours, emailDays, pdfHours, pdfDays,
      hoursDiff, daysDiff, hoursStatus, daysStatus, status,
      timesheetFileUrl, companyId: directCompanyId
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

    const result = await pool.query(`
      INSERT INTO automation_logs 
      (timestamp, sender_email, recipient_email, person_name, month, email_hours, email_days,
       pdf_hours, pdf_days, hours_diff, days_diff, hours_status, days_status, 
       status, company_id, timesheet_file_url, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW())
      RETURNING *
    `, [timestamp, senderEmail, recipientEmail, personName, month, emailHours, emailDays,
        pdfHours, pdfDays, hoursDiff, daysDiff, hoursStatus, daysStatus, 
        status, companyId, timesheetFileUrl || null]);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('N8N webhook error:', error);
    res.status(500).json({ error: 'Internal server error' });
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
              COALESCE(invoice_template, 'classic') as invoice_template
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
      invoice_template
    } = req.body;
    
    const result = await pool.query(
      `UPDATE companies 
       SET name = $1, address = $2, representative_name = $3, timesheet_deadline_day = $4, 
           company_vat = $5, company_email = $6, timesheet_email = $7, default_vat_rate = $8,  
           bank_name = $9, bank_iban = $10, bank_swift = $11, bank_address = $12,
           smtp_host = $13, smtp_port = $14, smtp_username = $15, smtp_password = $16,
           smtp_from_email = $17, smtp_from_name = $18, smtp_secure = $19, 
           invoice_template = $20, updated_at = NOW()
       WHERE id = $21
       RETURNING *`,
      [name, address, representative_name, timesheet_deadline_day, 
       company_vat, company_email, timesheet_email, default_vat_rate,
       bank_name, bank_iban, bank_swift, bank_address,
       smtp_host, smtp_port, smtp_username, smtp_password,
       smtp_from_email, smtp_from_name, smtp_secure,
       invoice_template || 'classic',
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
    const deadlineDate = new Date(checkingYear, checkingDate.getMonth(), deadlineDay);
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
             comp.invoice_template
      FROM invoices i
      JOIN contracts c ON i.contract_id = c.id
      JOIN consultants cons ON c.consultant_id = cons.id
      JOIN clients cli ON c.client_id = cli.id
      JOIN companies comp ON i.company_id = comp.id
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
      doc.rect(0, 0, pageWidth, 120).fill('#1e40af');
      
      doc.fontSize(24).font('Helvetica-Bold').fillColor('#ffffff')
         .text(sanitize(fromInfo.company), margin, 40, { width: pageWidth - 200 });
      
      doc.roundedRect(pageWidth - 180, 35, 130, 45, 6).fill('#3b82f6');
      doc.fontSize(9).fillColor('#ffffff').font('Helvetica')
         .text('INVOICE', pageWidth - 170, 43, { width: 110, align: 'center' });
      doc.fontSize(11).font('Helvetica-Bold')
         .text(sanitize(invoice.invoice_number), pageWidth - 170, 58, { width: 110, align: 'center' });
      
      doc.fillColor('#64748b').fontSize(10).font('Helvetica')
         .text(`Issue Date: ${invoiceDate}`, margin, 135);
      
      const leftCol = margin;
      const rightCol = pageWidth / 2 + 20;
      
      let billY = 165;
      doc.roundedRect(leftCol - 10, billY - 8, 230, 105, 6).fill('#f8fafc');
      doc.fillColor('#1e40af').fontSize(9).font('Helvetica-Bold').text('BILL TO', leftCol, billY);
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
      doc.fillColor('#1e40af').fontSize(9).font('Helvetica-Bold').text('FROM', rightCol, fromY);
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
      
      doc.rect(margin - 5, tableTop - 8, pageWidth - 90, 28).fill('#1e40af');
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
      doc.moveTo(summaryCol1, summaryTop).lineTo(pageWidth - margin, summaryTop).strokeColor('#1e40af').lineWidth(2).stroke();
      summaryTop += 12;
      doc.fillColor('#0f172a').fontSize(12).font('Helvetica-Bold');
      doc.text('TOTAL:', summaryCol1, summaryTop, { width: 100, align: 'right' });
      doc.fontSize(14).text(`€${parseFloat(invoice.total_amount).toFixed(2)}`, summaryCol2, summaryTop - 1, { width: 70, align: 'right' });
      
      const bankTop = summaryTop + 45;
      doc.fillColor('#1e40af').fontSize(11).font('Helvetica-Bold').text('Payment Details', margin, bankTop);
      doc.moveTo(margin, bankTop + 14).lineTo(margin + 120, bankTop + 14).strokeColor('#1e40af').lineWidth(2).stroke();
      
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
      doc.fontSize(16).font('Helvetica-Bold').fillColor('#0f172a')
         .text(`INVOICE ${invoice.invoice_number}`, margin, titleY, { align: 'center', width: pageWidth - (margin * 2) });
      doc.fontSize(11).font('Helvetica').fillColor('#64748b')
         .text(`Date: ${invoiceDate}`, margin, titleY + 22, { align: 'center', width: pageWidth - (margin * 2) });

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
      doc.moveTo(margin, 40).lineTo(pageWidth - margin, 40).strokeColor('#0f172a').lineWidth(2).stroke();
      
      doc.fontSize(18).font('Helvetica-Bold').fillColor('#0f172a')
         .text(sanitize(fromInfo.company), margin, 55);
      doc.fontSize(11).font('Helvetica').fillColor('#64748b')
         .text(`Invoice ${invoice.invoice_number}`, margin, 78);
      doc.text(`Date: ${invoiceDate}`, pageWidth - 180, 78, { width: 130, align: 'right' });
      
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
      doc.rect(0, 0, 6, pageHeight).fill('#059669');
      
      doc.fontSize(22).font('Helvetica-Bold').fillColor('#0f172a')
         .text(sanitize(fromInfo.company), margin + 10, 45);
      doc.fontSize(10).fillColor('#64748b').font('Helvetica')
         .text(sanitize(fromInfo.address) || '', margin + 10, 72, { width: 250, lineGap: 4 });
      if (fromInfo.vat) doc.text(`VAT: ${sanitize(fromInfo.vat)}`, margin + 10, 100);
      
      doc.roundedRect(pageWidth - 175, 40, 125, 75, 5).fill('#ecfdf5');
      doc.fillColor('#059669').fontSize(16).font('Helvetica-Bold').text('INVOICE', pageWidth - 165, 48, { width: 105, align: 'center' });
      doc.fillColor('#0f172a').fontSize(9).font('Helvetica').text(sanitize(invoice.invoice_number), pageWidth - 165, 70, { width: 105, align: 'center' });
      doc.fillColor('#64748b').fontSize(9).text(invoiceDate, pageWidth - 165, 95, { width: 105, align: 'center' });
      
      let yPos = 130;
      doc.fillColor('#059669').fontSize(10).font('Helvetica-Bold').text('BILL TO', margin + 10, yPos);
      doc.moveTo(margin + 10, yPos + 13).lineTo(margin + 60, yPos + 13).strokeColor('#059669').lineWidth(2).stroke();
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
             comp.smtp_from_email, comp.smtp_from_name, comp.smtp_secure, comp.address, comp.company_email, comp.representative_name
      FROM invoices i
      JOIN contracts c ON i.contract_id = c.id
      JOIN consultants cons ON c.consultant_id = cons.id
      JOIN clients cli ON c.client_id = cli.id
      JOIN companies comp ON i.company_id = comp.id
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
       status = CASE WHEN status = 'draft' THEN 'sent' ELSE status END, updated_at = NOW() WHERE id = $2`,
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
      process.env.JWT_SECRET || 'fallback-secret',
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
