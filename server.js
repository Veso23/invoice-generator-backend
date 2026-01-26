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
  allowedHeaders: ['Content-Type', 'Authorization']
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
  }
});

// Test database connection
pool.on('connect', () => {
  console.log('✅ Connected to Supabase database');
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

  // Create transporter
  const transporter = nodemailer.createTransport({
    host: companySettings.smtp_host,
    port: companySettings.smtp_port || 587,
    secure: companySettings.smtp_secure !== false, // true for 465, false for other ports
    auth: {
      user: companySettings.smtp_username,
      pass: companySettings.smtp_password
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
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.userId]);
    
    if (result.rows.length === 0) {
      return res.status(403).json({ error: 'Invalid token' });
    }

    req.user = result.rows[0];
    next();
  } catch (error) {
    console.error('Auth error:', error);
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// ✅ Admin-only middleware - MUST BE OUTSIDE authenticateToken
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Company middleware
const checkCompanyAccess = (req, res, next) => {
  req.companyId = req.user.company_id;
  next();
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

    // Check if user exists
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
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

      // Create user - FIRST USER IS ALWAYS ADMIN
      const userResult = await client.query(
        'INSERT INTO users (email, password_hash, first_name, last_name, company_id, role, active, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW()) RETURNING id, email, first_name, last_name, role, company_id, active',
        [email, hashedPassword, firstName, lastName, companyId, 'admin', true] // ✅ Always 'admin'
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

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
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

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role,
        companyId: user.company_id,
        active: user.active
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Consultant Routes
app.get('/api/consultants', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM consultants WHERE company_id = $1 ORDER BY created_at DESC',
      [req.companyId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get consultants error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/consultants', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const {
      firstName, lastName, companyName, companyAddress,
      companyVAT, iban, swift, phone, email, consultantContractId
    } = req.body;

    if (!firstName || !lastName || !companyName || !companyVAT) {
      return res.status(400).json({ error: 'Required fields: firstName, lastName, companyName, companyVAT' });
    }

    const result = await pool.query(
      `INSERT INTO consultants 
       (first_name, last_name, company_name, company_address, company_vat, iban, swift, phone, email, consultant_contract_id, company_id, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW()) 
       RETURNING *`,
      [firstName, lastName, companyName, companyAddress, companyVAT, iban, swift, phone, email, consultantContractId, req.companyId]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Create consultant error:', error);
    if (error.code === '23505') {
      res.status(400).json({ error: 'VAT number or Contract ID already exists' });
    } else {
      res.status(500).json({ error: 'Internal server error' });
    }
  }
});

// Update consultant (Admin only)
app.put('/api/consultants/:id', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      firstName, lastName, companyName, companyAddress,
      companyVAT, iban, swift, phone, email, consultantContractId
    } = req.body;

    // Verify consultant belongs to company
    const checkResult = await pool.query(
      'SELECT id FROM consultants WHERE id = $1 AND company_id = $2',
      [id, req.companyId]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Consultant not found' });
    }

    const result = await pool.query(
      `UPDATE consultants 
       SET first_name = $1, last_name = $2, company_name = $3, company_address = $4,
           company_vat = $5, iban = $6, swift = $7, phone = $8, email = $9,
           consultant_contract_id = $10, updated_at = NOW()
       WHERE id = $11 AND company_id = $12
       RETURNING *`,
      [firstName, lastName, companyName, companyAddress, companyVAT, iban, swift, 
       phone, email, consultantContractId, id, req.companyId]
    );

    res.json({ message: 'Consultant updated successfully', consultant: result.rows[0] });
  } catch (error) {
    console.error('Update consultant error:', error);
    if (error.code === '23505') {
      res.status(400).json({ error: 'VAT number or Contract ID already exists' });
    } else {
      res.status(500).json({ error: error.message });
    }
  }
});

// Delete consultant (Admin only)
app.delete('/api/consultants/:id', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;

    // Check if consultant has contracts
    const contractCheck = await pool.query(
      'SELECT COUNT(*) as count FROM contracts WHERE consultant_id = $1',
      [id]
    );

    if (parseInt(contractCheck.rows[0].count) > 0) {
      return res.status(400).json({ 
        error: 'Cannot delete consultant with existing contracts. Delete contracts first.' 
      });
    }

    // Verify consultant belongs to company
    const checkResult = await pool.query(
      'SELECT id FROM consultants WHERE id = $1 AND company_id = $2',
      [id, req.companyId]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Consultant not found' });
    }

    await pool.query('DELETE FROM consultants WHERE id = $1', [id]);
    res.json({ message: 'Consultant deleted successfully' });
  } catch (error) {
    console.error('Delete consultant error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Client Routes
app.get('/api/clients', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM clients WHERE company_id = $1 ORDER BY created_at DESC',
      [req.companyId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get clients error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/clients', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const {
      firstName, lastName, companyName, companyAddress,
      companyVAT, iban, swift, phone, email, clientContractId
    } = req.body;

    if (!firstName || !lastName || !companyName || !companyVAT) {
      return res.status(400).json({ error: 'Required fields: firstName, lastName, companyName, companyVAT' });
    }

    const result = await pool.query(
      `INSERT INTO clients 
       (first_name, last_name, company_name, company_address, company_vat, iban, swift, phone, email, client_contract_id, company_id, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW()) 
       RETURNING *`,
      [firstName, lastName, companyName, companyAddress, companyVAT, iban, swift, phone, email, clientContractId, req.companyId]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Create client error:', error);
    if (error.code === '23505') {
      res.status(400).json({ error: 'VAT number or Contract ID already exists' });
    } else {
      res.status(500).json({ error: 'Internal server error' });
    }
  }
});

// Update client (Admin only)
app.put('/api/clients/:id', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      firstName, lastName, companyName, companyAddress,
      companyVAT, iban, swift, phone, email, clientContractId
    } = req.body;

    // Verify client belongs to company
    const checkResult = await pool.query(
      'SELECT id FROM clients WHERE id = $1 AND company_id = $2',
      [id, req.companyId]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Client not found' });
    }

    const result = await pool.query(
      `UPDATE clients 
       SET first_name = $1, last_name = $2, company_name = $3, company_address = $4,
           company_vat = $5, iban = $6, swift = $7, phone = $8, email = $9,
           client_contract_id = $10, updated_at = NOW()
       WHERE id = $11 AND company_id = $12
       RETURNING *`,
      [firstName, lastName, companyName, companyAddress, companyVAT, iban, swift, 
       phone, email, clientContractId, id, req.companyId]
    );

    res.json({ message: 'Client updated successfully', client: result.rows[0] });
  } catch (error) {
    console.error('Update client error:', error);
    if (error.code === '23505') {
      res.status(400).json({ error: 'VAT number or Contract ID already exists' });
    } else {
      res.status(500).json({ error: error.message });
    }
  }
});

// Delete client (Admin only)
app.delete('/api/clients/:id', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;

    // Check if client has contracts
    const contractCheck = await pool.query(
      'SELECT COUNT(*) as count FROM contracts WHERE client_id = $1',
      [id]
    );

    if (parseInt(contractCheck.rows[0].count) > 0) {
      return res.status(400).json({ 
        error: 'Cannot delete client with existing contracts. Delete contracts first.' 
      });
    }

    // Verify client belongs to company
    const checkResult = await pool.query(
      'SELECT id FROM clients WHERE id = $1 AND company_id = $2',
      [id, req.companyId]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Client not found' });
    }

    await pool.query('DELETE FROM clients WHERE id = $1', [id]);
    res.json({ message: 'Client deleted successfully' });
  } catch (error) {
    console.error('Delete client error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Contract Routes
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
        c.vat_enabled,    -- Client VAT enabled
        c.vat_rate,       -- Client VAT rate
        c.consultant_vat_enabled,    -- ✅ NEW
        c.consultant_vat_rate,       -- ✅ NEW
        c.company_id,
        c.created_at,
        c.updated_at,
        cons.consultant_contract_id,  -- ✅ FROM CONSULTANTS TABLE
        cli.client_contract_id,       -- ✅ FROM CLIENTS TABLE
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
      WHERE c.company_id = $1
      ORDER BY c.created_at DESC
    `, [req.companyId]);

    res.json(result.rows);
  } catch (error) {
    console.error('Get contracts error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Timesheets Routes
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
      LEFT JOIN consultants c ON al.sender_email = c.email AND c.company_id = $1
      WHERE al.processed = false
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
      vatRate,                      // Don't set default here
      consultantVatEnabled = false,
      consultantVatRate            // Don't set default here
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
      vatEnabled, sanitizedVatRate,                    // ✅ Use sanitized value
      consultantVatEnabled, sanitizedConsultantVatRate, // ✅ Use sanitized value
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

// Update contract (Admin only)
app.put('/api/contracts/:id', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      contractNumber, consultantId, clientId, fromDate, toDate,
      purchasePrice, sellPrice, vatEnabled = false, vatRate,
      consultantVatEnabled = false, consultantVatRate
    } = req.body;

    // Verify contract belongs to company
    const checkResult = await pool.query(
      'SELECT id FROM contracts WHERE id = $1 AND company_id = $2',
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
       WHERE id = $12 AND company_id = $13
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

// Delete contract (Admin only)
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

    // Verify contract belongs to company
    const checkResult = await pool.query(
      'SELECT id FROM contracts WHERE id = $1 AND company_id = $2',
      [id, req.companyId]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Contract not found' });
    }

    await pool.query('DELETE FROM contracts WHERE id = $1', [id]);
    res.json({ message: 'Contract deleted successfully' });
  } catch (error) {
    console.error('Delete contract error:', error);
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

    // Verify consultant belongs to the same company
    const consultant = await pool.query(
      'SELECT * FROM consultants WHERE id = $1 AND company_id = $2',
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

// Update timesheet days
app.put('/api/timesheets/:id/days', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;
    const { days } = req.body;

    if (!days || isNaN(days) || days < 0) {
      return res.status(400).json({ error: 'Valid days value is required' });
    }

    const result = await pool.query(
      'UPDATE automation_logs SET pdf_days = $1 WHERE id = $2 RETURNING *',
      [days, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Timesheet not found' });
    }

    res.json({ success: true, message: 'Days updated successfully' });
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
    
    // ✅ ADD LOGGING
    console.log('Update month - Timesheet ID:', id);
    console.log('Update month - User Company ID:', req.companyId);
    console.log('Update month - Month:', month);
    
    // Validate month
    const validMonths = ['January', 'February', 'March', 'April', 'May', 'June', 
                        'July', 'August', 'September', 'October', 'November', 'December'];
    
    if (!validMonths.includes(month)) {
      return res.status(400).json({ error: 'Invalid month' });
    }
    
    // Check what the actual timesheet has
    const checkResult = await pool.query(
      'SELECT company_id FROM automation_logs WHERE id = $1',
      [id]
    );
    console.log('Timesheet company_id in DB:', checkResult.rows[0]?.company_id);
    
    const result = await pool.query(
      `UPDATE automation_logs 
       SET month = $1 
       WHERE id = $2 AND company_id = $3
       RETURNING *`,
      [month, id, req.companyId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Timesheet not found' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Update month error:', error);
    res.status(500).json({ error: error.message });
  }
});
// Invoice Generation
app.post('/api/invoices/generate/:contractId', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { contractId } = req.params;

    // Get contract with consultant and client details
const contractResult = await pool.query(`
  SELECT c.*, 
         cons.first_name as consultant_first_name, cons.last_name as consultant_last_name,
         cons.company_name as consultant_company, cons.company_address as consultant_address,
         cons.company_vat as consultant_vat, cons.iban as consultant_iban, cons.swift as consultant_swift,
         cli.first_name as client_first_name, cli.last_name as client_last_name,
         cli.company_name as client_company, cli.company_address as client_address,
         cli.company_vat as client_vat, cli.iban as client_iban, cli.swift as client_swift,
         comp.name as company_name, comp.address as company_address, comp.vat as company_vat,
         comp.default_vat_rate  -- ← ADD THIS LINE
  FROM contracts c
  JOIN consultants cons ON c.consultant_id = cons.id
  JOIN clients cli ON c.client_id = cli.id
  JOIN companies comp ON c.company_id = comp.id
  WHERE c.id = $1 AND c.company_id = $2
`, [contractId, req.companyId]);

    if (contractResult.rows.length === 0) {
      return res.status(404).json({ error: 'Contract not found' });
    }

    const contract = contractResult.rows[0];
    
    // Calculate days
    const fromDate = new Date(contract.from_date);
    const toDate = new Date(contract.to_date);
    const days = Math.ceil((toDate - fromDate) / (1000 * 60 * 60 * 24)) + 1;

    // Generate invoice numbers using the database function
    const consultantInvoiceNumber = `INV-CONS-${Date.now()}`;
    const clientInvoiceNumber = `INV-CLI-${Date.now()}`;

// Calculate amounts using company's default VAT rate
const vatRate = contract.default_vat_rate || 21.00;  // ← ADD THIS
const vatDecimal = vatRate / 100;

const consultantSubtotal = Math.round(contract.purchase_price * days * 100) / 100;
const consultantVAT = Math.round(consultantSubtotal * vatDecimal * 100) / 100;  // ✅ ROUNDED
const consultantTotal = Math.round((consultantSubtotal + consultantVAT) * 100) / 100;  // ✅ ROUNDED

const clientSubtotal = Math.round(contract.sell_price * days * 100) / 100;
const clientVAT = Math.round(clientSubtotal * vatDecimal * 100) / 100;  // ✅ ROUNDED
const clientTotal = Math.round((clientSubtotal + clientVAT) * 100) / 100;  // ✅ ROUNDED

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
    
    // Find consultant
    const consultantResult = await client.query(
      `SELECT * FROM consultants 
       WHERE LOWER(TRIM(email)) = $1 
       AND company_id = $2`,
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
      // Timesheet month is much later than current month - must be previous year
      // e.g., Current: January (0), Timesheet: December (11) -> previous year
      year = currentYear - 1;
    } else {
      // Normal case - same year
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
    
    // ✅ FIXED: Find contract by DATE RANGE, not by status
    // This matches the contract that was active DURING the timesheet period
    const contractResult = await client.query(
      `SELECT * FROM contracts 
       WHERE consultant_id = $1 
       AND company_id = $2 
       AND from_date <= $3
       AND to_date >= $4
       ORDER BY from_date DESC 
       LIMIT 1`,
      [consultant.id, req.companyId, periodFromStr, periodFromStr]
    );
    
    if (contractResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ 
        error: `No contract found for ${consultant.first_name} ${consultant.last_name} covering ${monthName} ${year}. ` +
               `Please ensure there is a contract with dates that include this period.`
      });
    }
    
    const contract = contractResult.rows[0];
    
    console.log(`Found contract: ${contract.contract_number} (${contract.from_date} to ${contract.to_date})`);
    
    // ✅ Generate invoice number with locking to prevent race condition
    const invoiceCountResult = await client.query(
      'SELECT COUNT(*) FROM invoices WHERE company_id = $1 FOR UPDATE',
      [req.companyId]
    );
    const invoiceCount = parseInt(invoiceCountResult.rows[0].count);
    const invoiceNumber = `INV-${year}-${String(invoiceCount + 1).padStart(4, '0')}`;
    
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
        `${invoiceNumber}-C`,
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
        `${invoiceNumber}-CL`,
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
// Add this new endpoint to your server.js

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
      LEFT JOIN consultants c ON LOWER(TRIM(al.sender_email)) = LOWER(TRIM(c.email)) AND c.company_id = $1
      LEFT JOIN invoices ci ON ci.timesheet_id = al.id AND ci.invoice_type = 'consultant'
      LEFT JOIN invoices cli ON cli.timesheet_id = al.id AND cli.invoice_type = 'client'
      WHERE al.company_id = $1 
         OR (al.company_id IS NULL AND c.company_id = $1)
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
      timesheetFileUrl
    } = req.body;

    // ✅ Find company by recipient email
    let companyId = null;
    if (recipientEmail) {
      const companyResult = await pool.query(
        'SELECT id FROM companies WHERE timesheet_email = $1',
        [recipientEmail.toLowerCase()]
      );
      
      if (companyResult.rows.length > 0) {
        companyId = companyResult.rows[0].id;
      } else {
        console.warn(`No company found for timesheet email: ${recipientEmail}`);
      }
    }
    
    // Fallback: match by sender email if recipient didn't match
    if (!companyId && senderEmail) {
      const consultantResult = await pool.query(
        'SELECT company_id FROM consultants WHERE email = $1 LIMIT 1',
        [senderEmail]
      );
      if (consultantResult.rows.length > 0) {
        companyId = consultantResult.rows[0].company_id;
      }
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
       LEFT JOIN consultants c ON LOWER(TRIM(al.sender_email)) = LOWER(TRIM(c.email))
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
              company_vat, company_email, default_vat_rate, 
              bank_name, bank_iban, bank_swift, bank_address,
              smtp_host, smtp_port, smtp_username, smtp_password,
              smtp_from_email, smtp_from_name, smtp_secure
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
      company_vat, company_email, timesheet_email, default_vat_rate,  // ← ADD timesheet_email
      bank_name, bank_iban, bank_swift, bank_address,
      smtp_host, smtp_port, smtp_username, smtp_password,
      smtp_from_email, smtp_from_name, smtp_secure
    } = req.body;
    
    const result = await pool.query(
      `UPDATE companies 
       SET name = $1, address = $2, representative_name = $3, timesheet_deadline_day = $4, 
           company_vat = $5, company_email = $6, timesheet_email = $7, default_vat_rate = $8,  
           bank_name = $9, bank_iban = $10, bank_swift = $11, bank_address = $12,
           smtp_host = $13, smtp_port = $14, smtp_username = $15, smtp_password = $16,
           smtp_from_email = $17, smtp_from_name = $18, smtp_secure = $19, updated_at = NOW()
       WHERE id = $20
       RETURNING *`,
      [name, address, representative_name, timesheet_deadline_day, 
       company_vat, company_email, timesheet_email, default_vat_rate,
       bank_name, bank_iban, bank_swift, bank_address,
       smtp_host, smtp_port, smtp_username, smtp_password,
       smtp_from_email, smtp_from_name, smtp_secure,
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
      LEFT JOIN consultants c ON al.sender_email = c.email AND c.company_id = $1
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
    // Get company settings for deadline
    const settingsResult = await pool.query(
      'SELECT timesheet_deadline_day FROM companies WHERE id = $1',
      [req.companyId]
    );
    
    const deadlineDay = settingsResult.rows[0]?.timesheet_deadline_day || 15;
    
    // Determine which month we're checking
    const now = new Date();
    const currentDay = now.getDate();
    const checkingDate = currentDay <= deadlineDay 
      ? new Date(now.getFullYear(), now.getMonth() - 1, 1) // Check previous month
      : new Date(now.getFullYear(), now.getMonth(), 1);     // Check current month
    
    const checkingMonth = checkingDate.toLocaleDateString('en-US', { month: 'long' });
    const checkingYear = checkingDate.getFullYear();
    
    // Calculate deadline date
    const deadlineDate = new Date(checkingYear, checkingDate.getMonth(), deadlineDay);
    const isOverdue = now > deadlineDate;
    
    // Get all consultants in active contracts
    const consultantsResult = await pool.query(
      `SELECT DISTINCT 
        c.id,
        c.first_name,
        c.last_name,
        c.company_name,
        c.email
       FROM consultants c
       INNER JOIN contracts ct ON c.id = ct.consultant_id
       WHERE c.company_id = $1 
       AND ct.status = 'active'
       ORDER BY c.last_name, c.first_name`,
      [req.companyId]
    );
    
    // ✅ FIXED: Get ALL timesheets, also check by consultant email without requiring company_id
    const timesheetsResult = await pool.query(
      `SELECT al.* FROM automation_logs al
       WHERE al.company_id = $1
       
       UNION
       
       SELECT al.* FROM automation_logs al
       INNER JOIN consultants c ON LOWER(TRIM(al.sender_email)) = LOWER(TRIM(c.email))
       WHERE c.company_id = $1
       
       ORDER BY created_at DESC`,
      [req.companyId]
    );
    
    const consultants = consultantsResult.rows.map(consultant => {
      // ✅ FIXED: Use case-insensitive email matching
      const normalizedConsultantEmail = consultant.email?.trim().toLowerCase();
      
      // Find matching timesheet - check both actual month AND estimated month
      const timesheet = timesheetsResult.rows.find(ts => {
        const normalizedSenderEmail = ts.sender_email?.trim().toLowerCase();
        if (normalizedSenderEmail !== normalizedConsultantEmail) return false;
        
        // If month is set in PDF, match exactly
        if (ts.month) {
          return ts.month.toLowerCase() === checkingMonth.toLowerCase();
        }
        
        // If month is NULL, estimate from created_at
        const createdDate = new Date(ts.created_at);
        const estimatedMonth = createdDate.toLocaleDateString('en-US', { month: 'long' });
        return estimatedMonth.toLowerCase() === checkingMonth.toLowerCase();
      });
      
      // ✅ FIXED: Also check if any timesheet for this consultant was already invoiced for this month
      const invoicedTimesheet = timesheetsResult.rows.find(ts => {
        const normalizedSenderEmail = ts.sender_email?.trim().toLowerCase();
        if (normalizedSenderEmail !== normalizedConsultantEmail) return false;
        if (!ts.invoice_generated) return false;
        
        // Match by month
        if (ts.month) {
          return ts.month.toLowerCase() === checkingMonth.toLowerCase();
        }
        return false;
      });
      
      let status;
      if (timesheet || invoicedTimesheet) {
        status = 'received';  // ✅ Green - timesheet exists or was already invoiced
      } else if (isOverdue) {
        status = 'overdue';   // Red - past deadline, no timesheet
      } else {
        status = 'waiting';   // Yellow - before deadline, no timesheet yet
      }
      
      return {
        ...consultant,
        status,
        checking_month: checkingMonth,
        checking_year: checkingYear,
        has_timesheet: !!(timesheet || invoicedTimesheet),
        timesheet_processed: (timesheet?.month || invoicedTimesheet?.month) ? true : false,
        invoice_generated: invoicedTimesheet?.invoice_generated || timesheet?.invoice_generated || false
      };
    });
    
    res.json({
      checking_month: checkingMonth,
      checking_year: checkingYear,
      deadline_day: deadlineDay,
      deadline_date: deadlineDate.toISOString(),
      is_overdue: isOverdue,
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
    
    // Get current invoice
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
    
    // Recalculate amounts
    const newVatAmount = vatEnabled ? (subtotal * vatRate / 100) : 0;
    const newTotal = subtotal + newVatAmount;
    
    // Update invoice
    const result = await pool.query(
      `UPDATE invoices 
       SET vat_rate = $1, 
           vat_amount = $2, 
           total_amount = $3,
           updated_at = NOW()
       WHERE id = $4 AND company_id = $5
       RETURNING *`,
      [vatRate, newVatAmount, newTotal, id, req.companyId]
    );
    
    res.json({ 
      message: 'VAT rate updated successfully', 
      invoice: result.rows[0] 
    });
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
    
    // Get current invoice
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
    
    // Recalculate amounts
    const newVatAmount = vatEnabled ? (subtotal * vatRate / 100) : 0;
    const newTotal = subtotal + newVatAmount;
    
    // Update invoice
    const result = await pool.query(
      `UPDATE invoices 
       SET vat_enabled = $1,
           vat_amount = $2, 
           total_amount = $3,
           updated_at = NOW()
       WHERE id = $4 AND company_id = $5
       RETURNING *`,
      [vatEnabled, newVatAmount, newTotal, id, req.companyId]
    );
    
    res.json({ 
      message: `VAT ${vatEnabled ? 'enabled' : 'disabled'} successfully`, 
      invoice: result.rows[0] 
    });
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
    
    // Get invoice with all related data
    const invoiceResult = await pool.query(`
      SELECT i.*,
             c.consultant_id, c.client_id,
             c.consultant_contract_id,
             c.client_contract_id,
             cons.first_name as consultant_first_name,
             cons.last_name as consultant_last_name,
             cons.company_name as consultant_company_name,
             cons.company_address as consultant_company_address,
             cons.company_vat as consultant_company_vat,
             cons.iban as consultant_iban,
             cons.swift as consultant_swift,
             cli.first_name as client_first_name,
             cli.last_name as client_last_name,
             cli.company_name as client_company_name,
             cli.company_address as client_company_address,
             cli.company_vat as client_company_vat,
             comp.name as company_name,
             comp.address as company_address,
             comp.company_vat as company_vat_number,
             comp.representative_name,
             comp.bank_name,
             comp.bank_iban,
             comp.bank_swift,
             comp.bank_address
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
    
    // Determine FROM and TO based on invoice type
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

    // Create PDF
    const doc = new PDFDocument({ margin: 50, size: 'A4' });
    const chunks = [];
    
    doc.on('data', chunk => chunks.push(chunk));
    doc.on('end', async () => {
      const pdfBuffer = Buffer.concat(chunks);
      
      const bucketName = invoice.invoice_type === 'consultant' ? 'consultant-invoices' : 'client-invoices';
      const fileName = `${invoice.invoice_number.replace(/\//g, '-')}.pdf`;
      
      const { data: uploadData, error: uploadError } = await supabase.storage
        .from(bucketName)
        .upload(fileName, pdfBuffer, {
          contentType: 'application/pdf',
          upsert: true
        });

      if (uploadError) {
        console.error('Upload error:', uploadError);
        return res.status(500).json({ error: 'Failed to upload PDF' });
      }

      const { data: urlData } = supabase.storage
        .from(bucketName)
        .getPublicUrl(fileName);

      const pdfUrl = urlData.publicUrl;

      await pool.query(
        'UPDATE invoices SET pdf_url = $1, updated_at = NOW() WHERE id = $2',
        [pdfUrl, id]
      );

      res.json({ message: 'PDF generated successfully', pdfUrl });
    });

    // Build PDF content
    const pageWidth = doc.page.width;
    const margin = 50;
    
    doc.fontSize(20).font('Helvetica-Bold').text(fromInfo.company, margin, 50);

    const leftCol = margin;
    const rightCol = pageWidth / 2 + 20;
    let yPos = 100;

    doc.fontSize(12).font('Helvetica-Bold').text('TO:', leftCol, yPos);
    yPos += 20;
    doc.fontSize(10).font('Helvetica');
    doc.text(toInfo.name, leftCol, yPos);
    yPos += 15;
    doc.text(toInfo.company, leftCol, yPos, { width: 220 });
    yPos += 15;
    const toAddressLines = doc.heightOfString(toInfo.address, { width: 220 });
    doc.text(toInfo.address, leftCol, yPos, { width: 220 });
    yPos += toAddressLines + 5;
    doc.text(`VAT: ${toInfo.vat}`, leftCol, yPos);

    let fromYPos = 100;
    doc.fontSize(12).font('Helvetica-Bold').text('FROM:', rightCol, fromYPos);
    fromYPos += 20;
    doc.fontSize(10).font('Helvetica');
    doc.text(fromInfo.company, rightCol, fromYPos, { width: 220 });
    fromYPos += 15;
    const fromAddressLines = doc.heightOfString(fromInfo.address, { width: 220 });
    doc.text(fromInfo.address, rightCol, fromYPos, { width: 220 });
    fromYPos += fromAddressLines + 5;
    doc.text(`VAT: ${fromInfo.vat}`, rightCol, fromYPos);
    fromYPos += 15;

    doc.fontSize(16).font('Helvetica-Bold')
       .text(`INVOICE No. ${invoice.invoice_number}`, margin, 240, { 
         align: 'center',
         width: pageWidth - (margin * 2)
       });
    
    const invoiceDate = new Date(invoice.period_to).toLocaleDateString('en-GB', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric'
    });
    doc.fontSize(12).font('Helvetica')
       .text(`Date: ${invoiceDate}`, margin, 265, { 
         align: 'center',
         width: pageWidth - (margin * 2)
       });

    const tableTop = 310;
    const col1 = margin;
    const col2 = margin + 50;
    const col3 = margin + 250;
    const col4 = margin + 330;
    const col5 = margin + 410;

    doc.fontSize(10).font('Helvetica-Bold');
    doc.text('No.', col1, tableTop);
    doc.text('Article / Description', col2, tableTop);
    doc.text('Days', col3, tableTop, { width: 60, align: 'right' });
    doc.text('Unit price', col4, tableTop, { width: 70, align: 'right' });
    doc.text('Total', col5, tableTop, { width: 70, align: 'right' });
    
    doc.moveTo(margin, tableTop + 15)
       .lineTo(pageWidth - margin, tableTop + 15)
       .stroke();

    const rowTop = tableTop + 25;
    doc.fontSize(9).font('Helvetica');
    doc.text('1', col1, rowTop);
    
    const periodMonth = new Date(invoice.period_to).toLocaleDateString('en-US', { month: 'long' });

    if (invoice.invoice_type === 'client') {
      const consultantName = `${invoice.consultant_first_name} ${invoice.consultant_last_name}`;
      doc.text(`IT Services/${consultantName} - ${periodMonth}`, col2, rowTop, { width: 230 });
      doc.text(`Contract: ${invoice.client_contract_id || 'N/A'}`, col2, rowTop + 12, { width: 230, fontSize: 8 });
    } else {
      doc.text(`IT Services - ${periodMonth}`, col2, rowTop, { width: 230 });
      doc.text(`Contract: ${invoice.consultant_contract_id || 'N/A'}`, col2, rowTop + 12, { width: 230, fontSize: 8 });
    }
    doc.text(invoice.days_worked.toString(), col3, rowTop, { width: 60, align: 'right' });
    doc.text(`€${parseFloat(invoice.daily_rate).toFixed(2)}`, col4, rowTop, { width: 70, align: 'right' });
    doc.text(`€${parseFloat(invoice.subtotal).toFixed(2)}`, col5, rowTop, { width: 70, align: 'right' });

    let summaryTop = rowTop + 50;
    if (invoice.vat_enabled) {
      doc.fontSize(10).font('Helvetica');
      doc.text(`VAT ${parseFloat(invoice.vat_rate).toFixed(0)}%`, col4, summaryTop, { width: 70, align: 'right' });
      doc.text(`€${parseFloat(invoice.vat_amount).toFixed(2)}`, col5, summaryTop, { width: 70, align: 'right' });
      summaryTop += 25;
    }

    doc.moveTo(col4, summaryTop - 5)
       .lineTo(pageWidth - margin, summaryTop - 5)
       .stroke();
    
    summaryTop += 10;
    doc.fontSize(11).font('Helvetica-Bold');
    doc.text('Total amount:', col4, summaryTop, { width: 70, align: 'right' });
    doc.text(`€${parseFloat(invoice.total_amount).toFixed(2)}`, col5, summaryTop, { width: 70, align: 'right' });

    const bankTop = summaryTop + 60;
    doc.fontSize(10).font('Helvetica-Bold').text('Please pay to:', margin, bankTop);
    doc.fontSize(9).font('Helvetica');
    doc.text(`Bank: ${fromInfo.iban ? (invoice.invoice_type === 'consultant' ? 'N/A' : invoice.bank_name || 'N/A') : 'N/A'}`, margin, bankTop + 20);
    doc.text(`IBAN: ${fromInfo.iban || 'N/A'}`, margin, bankTop + 35);
    doc.text(`SWIFT: ${fromInfo.swift || 'N/A'}`, margin, bankTop + 50);

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
      SELECT i.*,
             c.consultant_id, c.client_id,
             cons.first_name as consultant_first_name,
             cons.last_name as consultant_last_name,
             cons.company_name as consultant_company_name,
             cons.email as consultant_email,
             cli.first_name as client_first_name,
             cli.last_name as client_last_name,
             cli.company_name as client_company_name,
             cli.email as client_email,
             comp.name as company_name,
             comp.address as company_address,
             comp.company_email,
             comp.representative_name,
             comp.smtp_host,
             comp.smtp_port,
             comp.smtp_username,
             comp.smtp_password,
             comp.smtp_from_email,
             comp.smtp_from_name,
             comp.smtp_secure
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
    
    if (!invoice.pdf_url) {
      return res.status(400).json({ error: 'Please generate PDF before sending email' });
    }
    
    let recipientEmail, recipientName;
    if (invoice.invoice_type === 'consultant') {
      recipientEmail = invoice.consultant_email;
      recipientName = `${invoice.consultant_first_name} ${invoice.consultant_last_name}`;
    } else {
      recipientEmail = invoice.client_email;
      recipientName = `${invoice.client_first_name} ${invoice.client_last_name}`;
    }
    
    if (!recipientEmail) {
      return res.status(400).json({ error: 'Recipient email not found' });
    }
    
    await sendInvoiceEmail(invoice, invoice, recipientEmail, recipientName);
    
    await pool.query(
      `UPDATE invoices 
       SET email_sent = true, 
           email_sent_at = NOW(), 
           email_sent_to = $1,
           status = CASE WHEN status = 'draft' THEN 'sent' ELSE status END,
           updated_at = NOW()
       WHERE id = $2`,
      [recipientEmail, id]
    );
    
    res.json({ 
      message: 'Email sent successfully',
      recipient: recipientEmail
    });
    
  } catch (error) {
    console.error('Send email error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// USER MANAGEMENT ENDPOINTS (Admin Only)
// ============================================

// Get all users in company (Admin only)
app.get('/api/users', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.id, u.email, u.first_name, u.last_name, u.role, u.active, u.created_at, u.last_login,
             creator.first_name as created_by_first_name, creator.last_name as created_by_last_name
      FROM users u
      LEFT JOIN users creator ON u.created_by = creator.id
      WHERE u.company_id = $1
      ORDER BY u.created_at DESC
    `, [req.companyId]);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create operator account (Admin only)
app.post('/api/users', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const { email, password, firstName, lastName } = req.body;

    if (!email || !password || !firstName || !lastName) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if email already exists
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Email already exists' });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create operator
    const result = await pool.query(`
      INSERT INTO users 
      (email, password_hash, first_name, last_name, company_id, role, active, created_by, created_at)
      VALUES ($1, $2, $3, $4, $5, 'operator', true, $6, NOW())
      RETURNING id, email, first_name, last_name, role, active, created_at
    `, [email, hashedPassword, firstName, lastName, req.companyId, req.user.id]);

    res.status(201).json({
      message: 'Operator created successfully',
      user: result.rows[0]
    });
  } catch (error) {
    console.error('Create operator error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Toggle user active status (Admin only)
app.put('/api/users/:id/toggle-active', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;

    // Check user belongs to same company
    const userCheck = await pool.query(
      'SELECT * FROM users WHERE id = $1 AND company_id = $2',
      [id, req.companyId]
    );

    if (userCheck.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userCheck.rows[0];

    // Prevent admin from disabling themselves
    if (user.id === req.user.id) {
      return res.status(400).json({ error: 'You cannot disable your own account' });
    }

    // Toggle active status
    const result = await pool.query(
      'UPDATE users SET active = NOT active, updated_at = NOW() WHERE id = $1 RETURNING *',
      [id]
    );

    res.json({
      message: `User ${result.rows[0].active ? 'enabled' : 'disabled'} successfully`,
      user: result.rows[0]
    });
  } catch (error) {
    console.error('Toggle user active error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete user (Admin only)
app.delete('/api/users/:id', authenticateToken, requireAdmin, checkCompanyAccess, async (req, res) => {
  try {
    const { id } = req.params;

    // Check user belongs to same company
    const userCheck = await pool.query(
      'SELECT * FROM users WHERE id = $1 AND company_id = $2',
      [id, req.companyId]
    );

    if (userCheck.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userCheck.rows[0];

    // Prevent admin from deleting themselves
    if (user.id === req.user.id) {
      return res.status(400).json({ error: 'You cannot delete your own account' });
    }

    // Delete user
    await pool.query('DELETE FROM users WHERE id = $1', [id]);

    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Change password (Both roles)
app.put('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new passwords are required' });
    }

    // Get user
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    const user = result.rows[0];

    // Verify current password
    const isValid = await bcrypt.compare(currentPassword, user.password_hash);
    if (!isValid) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Hash new password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update password
    await pool.query(
      'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
      [hashedPassword, req.user.id]
    );

    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Change password error:', error);
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
  console.log(`🔗 Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;
