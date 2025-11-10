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

// Auth Routes
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

      // Create user
      const userResult = await client.query(
        'INSERT INTO users (email, password_hash, first_name, last_name, company_id, role, created_at) VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING id, email, first_name, last_name, role, company_id',
        [email, hashedPassword, firstName, lastName, companyId, 'admin']
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
          companyId: user.company_id
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
        companyId: user.company_id
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

app.post('/api/consultants', authenticateToken, checkCompanyAccess, async (req, res) => {
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

app.post('/api/clients', authenticateToken, checkCompanyAccess, async (req, res) => {
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


app.post('/api/contracts', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const {
      contractNumber,  // ← FROM USER INPUT
      consultantId, clientId, fromDate, toDate,
      purchasePrice, sellPrice
    } = req.body;

    if (!contractNumber || !consultantId || !clientId || !fromDate || !toDate || !purchasePrice || !sellPrice) {
      return res.status(400).json({ error: 'All fields including contract number are required' });
    }

    // Generate internal unique IDs (these can be auto-generated for database constraints)
    const timestamp = Date.now();
    const consultantContractId = `CONS-${timestamp}`;
    const clientContractId = `CLI-${timestamp}`;

    const result = await pool.query(`
      INSERT INTO contracts 
      (contract_number, consultant_id, client_id, from_date, to_date, purchase_price, sell_price, 
       consultant_contract_id, client_contract_id, company_id, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW()) 
      RETURNING *
    `, [
      contractNumber,  // ← USER'S NUMBER (e.g., "CNT-2025-001")
      consultantId, 
      clientId, 
      fromDate, 
      toDate, 
      purchasePrice, 
      sellPrice, 
      consultantContractId,  // Internal only
      clientContractId,      // Internal only
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

const consultantSubtotal = contract.purchase_price * days;
const consultantVAT = consultantSubtotal * vatDecimal;  // ← CHANGED
const consultantTotal = consultantSubtotal + consultantVAT;

const clientSubtotal = contract.sell_price * days;
const clientVAT = clientSubtotal * vatDecimal;  // ← CHANGED
const clientTotal = clientSubtotal + clientVAT;

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
  try {
    const { id } = req.params;

    // Get timesheet with approved days
    const timesheetResult = await pool.query('SELECT * FROM automation_logs WHERE id = $1', [id]);
    if (timesheetResult.rows.length === 0) {
      return res.status(404).json({ error: 'Timesheet not found' });
    }
    const timesheet = timesheetResult.rows[0];

    // Must be matched to consultant
    if (!timesheet.sender_email) {
      return res.status(400).json({ error: 'Please match timesheet to consultant first' });
    }

    // Get consultant
    const consultantResult = await pool.query(
      'SELECT * FROM consultants WHERE email = $1 AND company_id = $2',
      [timesheet.sender_email, req.companyId]
    );
    if (consultantResult.rows.length === 0) {
      return res.status(404).json({ error: 'Consultant not found' });
    }
    const consultant = consultantResult.rows[0];

    // Get active contract
    const contractResult = await pool.query(
      `SELECT c.*, cli.first_name as client_first_name, cli.last_name as client_last_name,
              cli.company_name as client_company_name
       FROM contracts c JOIN clients cli ON c.client_id = cli.id
       WHERE c.consultant_id = $1 AND c.company_id = $2 AND c.status = 'active'
       ORDER BY c.created_at DESC LIMIT 1`,
      [consultant.id, req.companyId]
    );
    if (contractResult.rows.length === 0) {
      return res.status(404).json({ error: 'No active contract found' });
    }
    const contract = contractResult.rows[0];

    // Use ACTUAL days from timesheet (not contract dates!)
    const daysWorked = parseFloat(timesheet.pdf_days || timesheet.email_days || 0);
    if (daysWorked <= 0) {
      return res.status(400).json({ error: 'Invalid days worked in timesheet' });
    }

    // Parse month from timesheet (handle both formats)
    const monthStr = timesheet.month || '';
    let year, month;

    if (monthStr.includes('-')) {
      [year, month] = monthStr.split('-');
    } else {
      const monthNames = ['January', 'February', 'March', 'April', 'May', 'June', 
                          'July', 'August', 'September', 'October', 'November', 'December'];
      const monthIndex = monthNames.findIndex(m => m.toLowerCase() === monthStr.toLowerCase());
      
      if (monthIndex === -1) {
        return res.status(400).json({ error: 'Invalid month format in timesheet' });
      }
      
      year = new Date().getFullYear().toString();
      month = (monthIndex + 1).toString();
    }

    const periodFrom = new Date(parseInt(year), parseInt(month) - 1, 1);
    const periodTo = new Date(parseInt(year), parseInt(month), 0);

    // ✅ GENERATE CONSULTANT INVOICE NUMBER (per consultant)
    // Format: INV-ConsultantName-001, INV-ConsultantName-002, etc.
    const consultantName = `${consultant.first_name}${consultant.last_name}`.replace(/\s+/g, '');
    const consultantInvoiceCountResult = await pool.query(`
      SELECT COUNT(*) as count 
      FROM invoices i
      JOIN contracts c ON i.contract_id = c.id
      WHERE c.consultant_id = $1 AND i.invoice_type = 'consultant'
    `, [consultant.id]);
    const consultantInvoiceCount = parseInt(consultantInvoiceCountResult.rows[0].count) + 1;
    const consultantInvoiceNumber = `INV-${consultantName}-${consultantInvoiceCount.toString().padStart(3, '0')}`;

    // ✅ GENERATE CLIENT INVOICE NUMBER (company-wide per year)
    // Format: INV-2025-001, INV-2025-002, etc.
    const currentYear = new Date().getFullYear();
    const clientInvoiceCountResult = await pool.query(`
      SELECT COUNT(*) as count 
      FROM invoices
      WHERE invoice_type = 'client' 
        AND company_id = $1
        AND EXTRACT(YEAR FROM invoice_date) = $2
    `, [req.companyId, currentYear]);
    const clientInvoiceCount = parseInt(clientInvoiceCountResult.rows[0].count) + 1;
    const clientInvoiceNumber = `INV-${currentYear}-${clientInvoiceCount.toString().padStart(3, '0')}`;

// Get company default VAT rate
const companyResult = await pool.query(
  'SELECT default_vat_rate FROM companies WHERE id = $1',
  [req.companyId]
);
const vatRate = companyResult.rows[0]?.default_vat_rate || 21.00;
const vatDecimal = vatRate / 100;

// Calculate amounts for CONSULTANT invoice (purchase)
const consultantSubtotal = contract.purchase_price * daysWorked;
const consultantVAT = consultantSubtotal * vatDecimal;  // ← CHANGED
const consultantTotal = consultantSubtotal + consultantVAT;

// Calculate amounts for CLIENT invoice (sell)
const clientSubtotal = contract.sell_price * daysWorked;
const clientVAT = clientSubtotal * vatDecimal;  // ← CHANGED
const clientTotal = clientSubtotal + clientVAT;

// Create BOTH invoices
await pool.query(`
  INSERT INTO invoices 
  (invoice_number, contract_id, invoice_type, invoice_date, period_from, period_to,
   days_worked, daily_rate, subtotal, vat_rate, vat_amount, total_amount, company_id, created_by, created_at)
  VALUES 
  ($1, $2, 'consultant', CURRENT_DATE, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW()),
  ($13, $2, 'client', CURRENT_DATE, $3, $4, $5, $14, $15, $8, $16, $17, $11, $12, NOW())
`, [
  consultantInvoiceNumber, contract.id, periodFrom, periodTo, daysWorked,
  contract.purchase_price, consultantSubtotal, vatRate, consultantVAT, consultantTotal, req.companyId, req.user.id,
  clientInvoiceNumber, contract.sell_price, clientSubtotal, clientVAT, clientTotal
]);

    // Mark timesheet as processed
    await pool.query(
      'UPDATE automation_logs SET invoice_generated = true, processed = true WHERE id = $1',
      [id]
    );

    res.json({ 
      message: 'Invoices generated successfully from timesheet', 
      consultantInvoice: consultantInvoiceNumber,
      clientInvoice: clientInvoiceNumber,
      daysUsed: daysWorked
    });

  } catch (error) {
    console.error('Generate invoice from timesheet error:', error);
    res.status(500).json({ error: error.message });
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
      timestamp, senderEmail, personName, month,
      emailHours, emailDays, pdfHours, pdfDays,
      hoursDiff, daysDiff, hoursStatus, daysStatus, status
    } = req.body;

    // 🔍 Find company_id by matching consultant email
    let companyId = null;
    if (senderEmail) {
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
      (timestamp, sender_email, person_name, month, email_hours, email_days,
       pdf_hours, pdf_days, hours_diff, days_diff, hours_status, days_status, status, company_id, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW())
      RETURNING *
    `, [timestamp, senderEmail, personName, month, emailHours, emailDays,
        pdfHours, pdfDays, hoursDiff, daysDiff, hoursStatus, daysStatus, status, companyId]);

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
app.put('/api/company/settings', authenticateToken, checkCompanyAccess, async (req, res) => {
  try {
    const { 
      name, address, representative_name, timesheet_deadline_day, 
      company_vat, company_email, default_vat_rate, 
      bank_name, bank_iban, bank_swift, bank_address,
      smtp_host, smtp_port, smtp_username, smtp_password,
      smtp_from_email, smtp_from_name, smtp_secure
    } = req.body;
    
    const result = await pool.query(
      `UPDATE companies 
       SET name = $1, 
           address = $2,
           representative_name = $3,
           timesheet_deadline_day = $4, 
           company_vat = $5, 
           company_email = $6,
           default_vat_rate = $7,
           bank_name = $8,
           bank_iban = $9,
           bank_swift = $10,
           bank_address = $11,
           smtp_host = $12,
           smtp_port = $13,
           smtp_username = $14,
           smtp_password = $15,
           smtp_from_email = $16,
           smtp_from_name = $17,
           smtp_secure = $18,
           updated_at = NOW()
       WHERE id = $19
       RETURNING *`,
      [name, address, representative_name, timesheet_deadline_day, 
       company_vat, company_email, default_vat_rate, 
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
    // Get company deadline setting
    const companyResult = await pool.query(
      'SELECT timesheet_deadline_day FROM companies WHERE id = $1',
      [req.companyId]
    );
    const deadlineDay = companyResult.rows[0]?.timesheet_deadline_day || 15;
        
    // Get all consultants with active contracts
    const consultantsResult = await pool.query(`
      SELECT DISTINCT
        cons.id,
        cons.first_name,
        cons.last_name,
        cons.company_name,
        cons.email
      FROM consultants cons
      JOIN contracts c ON c.consultant_id = cons.id
      WHERE c.status = 'active' AND cons.company_id = $1
      ORDER BY cons.first_name, cons.last_name
    `, [req.companyId]);
    
    // Calculate status for each consultant
    const now = new Date();
    const currentMonth = now.getMonth(); // 0-11
    const currentYear = now.getFullYear();
    
    // We're checking for LAST month's timesheet
    let checkMonth = currentMonth - 1;
    let checkYear = currentYear;
    if (checkMonth < 0) {
      checkMonth = 11; // December
      checkYear -= 1;
    }
    
    // Calculate deadline date (e.g., October 15 for September timesheets)
    const deadlineMonth = currentMonth;
    const deadlineYear = currentYear;
    const deadline = new Date(deadlineYear, deadlineMonth, deadlineDay);
    
    // Month names for display
    const monthNames = ['January', 'February', 'March', 'April', 'May', 'June',
                       'July', 'August', 'September', 'October', 'November', 'December'];
    const checkingMonthName = monthNames[checkMonth];
    
    // Get all timesheets for the month we're checking
    const timesheetsResult = await pool.query(`
  SELECT sender_email, month, pdf_days, email_days, created_at
  FROM automation_logs
  WHERE company_id = $1 OR company_id IS NULL
`, [req.companyId]);
    
    // Build status for each consultant
    const consultantStatuses = consultantsResult.rows.map(consultant => {
      // Find timesheet for this consultant for the checking month
      const timesheet = timesheetsResult.rows.find(ts => {
        if (ts.sender_email !== consultant.email) return false;
        
        // Check if month matches
        const tsMonth = ts.month?.toLowerCase();
        return tsMonth === checkingMonthName.toLowerCase();
      });
      
      let status, statusText;
      if (timesheet) {
        status = 'received'; // GREEN
        statusText = 'Received';
      } else if (now < deadline) {
        status = 'waiting'; // YELLOW
        statusText = 'Waiting';
      } else {
        status = 'overdue'; // RED
        statusText = 'Overdue';
      }
      
      return {
        ...consultant,
        checking_month: checkingMonthName,
        checking_year: checkYear,
        status,
        status_text: statusText,
        timesheet_id: timesheet?.id || null,
        days_worked: timesheet?.pdf_days || timesheet?.email_days || null,
        deadline_date: deadline.toISOString().split('T')[0]
      };
    });
    
    res.json({
      deadline_day: deadlineDay,
      checking_month: checkingMonthName,
      checking_year: checkYear,
      consultants: consultantStatuses
    });
    
  } catch (error) {
    console.error('Get timesheet status error:', error);
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
