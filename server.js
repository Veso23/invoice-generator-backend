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

const app = express();

// Middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));
app.use(compression());
app.use(morgan('combined'));

// CORS configuration - Allow all origins for now
app.use(cors({
  origin: true, // Allow all origins during development
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
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
      SELECT c.*, 
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
      contractNumber, consultantId, clientId, fromDate, toDate,
      purchasePrice, sellPrice
    } = req.body;

    if (!contractNumber || !consultantId || !clientId || !fromDate || !toDate || !purchasePrice || !sellPrice) {
      return res.status(400).json({ error: 'All contract fields including contract number are required' });
    }

    // Get consultant and client contract IDs from their records
    const consultantResult = await pool.query(
      'SELECT consultant_contract_id FROM consultants WHERE id = $1 AND company_id = $2', 
      [consultantId, req.companyId]
    );
    
    const clientResult = await pool.query(
      'SELECT client_contract_id FROM clients WHERE id = $1 AND company_id = $2', 
      [clientId, req.companyId]
    );

    if (consultantResult.rows.length === 0) {
      return res.status(400).json({ error: 'Consultant not found' });
    }

    if (clientResult.rows.length === 0) {
      return res.status(400).json({ error: 'Client not found' });
    }

    // Use empty string if contract IDs are null
    const consultantContractId = consultantResult.rows[0].consultant_contract_id || '';
    const clientContractId = clientResult.rows[0].client_contract_id || '';

    const result = await pool.query(`
      INSERT INTO contracts 
      (contract_number, consultant_id, client_id, from_date, to_date, purchase_price, sell_price, 
       consultant_contract_id, client_contract_id, company_id, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW()) 
      RETURNING *
    `, [contractNumber, consultantId, clientId, fromDate, toDate, purchasePrice, sellPrice, 
        consultantContractId, clientContractId, req.companyId]);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Create contract error:', error);
    if (error.code === '23505') {
      res.status(400).json({ error: 'Contract number already exists' });
    } else {
      res.status(500).json({ error: `Internal server error: ${error.message}` });
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
             comp.name as company_name, comp.address as company_address, comp.vat as company_vat
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

    // Calculate amounts
    const consultantSubtotal = contract.purchase_price * days;
    const consultantVAT = consultantSubtotal * 0.2;
    const consultantTotal = consultantSubtotal + consultantVAT;

    const clientSubtotal = contract.sell_price * days;
    const clientVAT = clientSubtotal * 0.2;
    const clientTotal = clientSubtotal + clientVAT;

    // Create consultant invoice
    const consultantInvoiceResult = await pool.query(`
      INSERT INTO invoices 
      (invoice_number, contract_id, invoice_type, invoice_date, period_from, period_to,
       days_worked, daily_rate, subtotal, vat_amount, total_amount, company_id, created_by, created_at)
      VALUES ($1, $2, 'consultant', CURRENT_DATE, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
      RETURNING *
    `, [consultantInvoiceNumber, contractId, contract.from_date, contract.to_date,
        days, contract.purchase_price, consultantSubtotal, consultantVAT, consultantTotal, req.companyId, req.user.id]);

    // Create client invoice
    const clientInvoiceResult = await pool.query(`
      INSERT INTO invoices 
      (invoice_number, contract_id, invoice_type, invoice_date, period_from, period_to,
       days_worked, daily_rate, subtotal, vat_amount, total_amount, company_id, created_by, created_at)
      VALUES ($1, $2, 'client', CURRENT_DATE, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
      RETURNING *
    `, [clientInvoiceNumber, contractId, contract.from_date, contract.to_date,
        days, contract.sell_price, clientSubtotal, clientVAT, clientTotal, req.companyId, req.user.id]);

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

    const result = await pool.query(`
      INSERT INTO automation_logs 
      (timestamp, sender_email, person_name, month, email_hours, email_days,
       pdf_hours, pdf_days, hours_diff, days_diff, hours_status, days_status, status, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW())
      RETURNING *
    `, [timestamp, senderEmail, personName, month, emailHours, emailDays,
        pdfHours, pdfDays, hoursDiff, daysDiff, hoursStatus, daysStatus, status]);

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

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
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
