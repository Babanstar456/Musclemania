const express = require('express');
const mysql = require('mysql2/promise');
const admin = require('firebase-admin');
const cors = require('cors');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(cors());

// Initialize Firebase Admin SDK from serviceAccount.json file
const serviceAccountPath =JSON.parse(process.env.FIREBASE_CONFIG);
try {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccountPath)
  });
  console.log('Firebase Admin SDK initialized successfully');
} catch (error) {
  console.error('Error initializing Firebase Admin SDK:', error);
  process.exit(1);
}

// Database configuration
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'your_database',
  charset: 'utf8mb4',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

// Create connection pool
const pool = mysql.createPool(dbConfig);

// Test database connection
async function testConnection() {
  try {
    const connection = await pool.getConnection();
    console.log('Database connected successfully');
    connection.release();
  } catch (error) {
    console.error('Database connection failed:', error);
    process.exit(1);
  }
}

// Middleware to verify Firebase token
const verifyFirebaseToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1]; // Bearer token
    if (!token) {
      return res.status(401).json({ 
        success: false, 
        error: 'No token provided' 
      });
    }
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Error verifying Firebase token:', error);
    return res.status(401).json({ 
      success: false, 
      error: 'Invalid token' 
    });
  }
};

// Middleware to check if user is admin
const verifyAdminToken = async (req, res, next) => {
  try {
    const firebase_uid = req.user.uid;
    
    // Check if user is admin in database
    const [adminCheck] = await pool.execute(
      'SELECT is_admin FROM gym_users WHERE firebase_uid = ?',
      [firebase_uid]
    );

    if (adminCheck.length === 0) {
      return res.status(403).json({
        success: false,
        error: 'User not found in database'
      });
    }

    if (!adminCheck[0].is_admin) {
      return res.status(403).json({
        success: false,
        error: 'Access denied: Admin privileges required'
      });
    }

    req.isAdmin = true;
    next();
  } catch (error) {
    console.error('Error verifying admin privileges:', error);
    return res.status(500).json({
      success: false,
      error: 'Error verifying admin privileges'
    });
  }
};

// Utility function to format date for MySQL
function formatDateForMySQL(dateStr) {
  const date = new Date(dateStr);
  return date.toISOString().slice(0, 7) + '-01'; // Format as YYYY-MM-01
}

// Utility function to format date (YYYY-MM-DD)
function formatDate(dateStr) {
  const date = new Date(dateStr);
  return date.toISOString().slice(0, 10); // Format as YYYY-MM-DD
}

// Utility function to validate date format
function isValidDate(dateString) {
  const regex = /^\d{4}-\d{2}-\d{2}$/;
  if (!regex.test(dateString)) return false;
  const date = new Date(dateString);
  const timestamp = date.getTime();
  if (typeof timestamp !== 'number' || Number.isNaN(timestamp)) return false;
  return dateString === date.toISOString().slice(0, 10);
}

// ==================== USER MANAGEMENT ROUTES ====================

// Route to get user profile (Firebase data + Database data)
app.get('/api/user/profile', verifyFirebaseToken, async (req, res) => {
  try {
    const firebase_uid = req.user.uid;
    
    // Get user data from Firebase
    const firebaseUser = await admin.auth().getUser(firebase_uid);
    const firebaseData = {
      name: firebaseUser.displayName || null,
      email: firebaseUser.email || null,
      firebase_uid: firebaseUser.uid,
      email_verified: firebaseUser.emailVerified,
      photo_url: firebaseUser.photoURL || null,
      provider_data: firebaseUser.providerData
    };

    // Get additional data from database
    const connection = await pool.getConnection();
    try {
      const [rows] = await connection.execute(
        'SELECT name, Phone, Address, DOB, member_since, is_admin FROM gym_users WHERE firebase_uid = ?',
        [firebase_uid]
      );

      const dbData = rows.length > 0 ? rows[0] : {
        name: null,
        Phone: null,
        Address: null,
        DOB: null,
        member_since: null,
        is_admin: 0
      };

      // Combine Firebase and database data (prioritize database name if available)
      const userProfile = {
        ...firebaseData,
        name: dbData.name || firebaseData.name,
        Phone: dbData.Phone,
        Address: dbData.Address,
        DOB: dbData.DOB,
        member_since: dbData.member_since,
        is_admin: Boolean(dbData.is_admin)
      };

      res.json({
        success: true,
        data: userProfile
      });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch user profile' 
    });
  }
});

// Route to update user data in database
app.put('/api/user/profile', verifyFirebaseToken, async (req, res) => {
  try {
    const firebase_uid = req.user.uid;
    const { name, Phone, Address, DOB, member_since } = req.body;

    const connection = await pool.getConnection();
    try {
      // Check if user exists
      const [existingUser] = await connection.execute(
        'SELECT firebase_uid FROM gym_users WHERE firebase_uid = ?',
        [firebase_uid]
      );

      if (existingUser.length === 0) {
        // Insert new user (is_admin defaults to 0)
        await connection.execute(
          'INSERT INTO gym_users (firebase_uid, name, Phone, Address, DOB, member_since) VALUES (?, ?, ?, ?, ?, ?)',
          [firebase_uid, name || null, Phone || null, Address || null, DOB || null, member_since || null]
        );
      } else {
        // Update existing user
        const dbUpdates = [];
        const dbParams = [];

        if (name !== undefined) {
          dbUpdates.push('name = ?');
          dbParams.push(name);
        }
        if (Phone !== undefined) {
          dbUpdates.push('Phone = ?');
          dbParams.push(Phone);
        }
        if (Address !== undefined) {
          dbUpdates.push('Address = ?');
          dbParams.push(Address);
        }
        if (DOB !== undefined) {
          dbUpdates.push('DOB = ?');
          dbParams.push(DOB);
        }
        if (member_since !== undefined) {
          dbUpdates.push('member_since = ?');
          dbParams.push(member_since);
        }

        if (dbUpdates.length === 0) {
          return res.status(400).json({
            success: false,
            message: 'No valid fields to update'
          });
        }

        dbParams.push(firebase_uid);

        await connection.execute(
          `UPDATE gym_users SET ${dbUpdates.join(', ')} WHERE firebase_uid = ?`,
          dbParams
        );
      }

      res.json({
        success: true,
        message: 'User profile updated successfully'
      });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error updating user profile:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to update user profile' 
    });
  }
});

// Route to get all users (Admin only)
app.get('/api/users', verifyFirebaseToken, verifyAdminToken, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    try {
      const [rows] = await connection.execute(
        'SELECT firebase_uid, name, Phone, Address, DOB, member_since, is_admin FROM gym_users'
      );

      // Get Firebase data for each user
      const usersWithFirebaseData = await Promise.all(
        rows.map(async (user) => {
          try {
            const firebaseUser = await admin.auth().getUser(user.firebase_uid);
            return {
              name: user.name || firebaseUser.displayName || null,
              email: firebaseUser.email || null,
              firebase_uid: user.firebase_uid,
              Phone: user.Phone,
              Address: user.Address,
              DOB: user.DOB,
              member_since: user.member_since,
              is_admin: Boolean(user.is_admin),
              email_verified: firebaseUser.emailVerified
            };
          } catch (firebaseError) {
            console.warn(`Firebase user not found for UID: ${user.firebase_uid}`);
            return {
              name: user.name || null,
              email: null,
              firebase_uid: user.firebase_uid,
              Phone: user.Phone,
              Address: user.Address,
              DOB: user.DOB,
              member_since: user.member_since,
              is_admin: Boolean(user.is_admin),
              email_verified: false,
              error: 'Firebase user not found'
            };
          }
        })
      );

      res.json({
        success: true,
        data: usersWithFirebaseData,
        count: usersWithFirebaseData.length
      });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch users' 
    });
  }
});

// POST - Create new user (Admin only)
app.post('/api/admin/users', verifyFirebaseToken, verifyAdminToken, async (req, res) => {
  try {
    const { name, Phone, Address, DOB, member_since, is_admin = false } = req.body;

    const connection = await pool.getConnection();
    try {
      // Generate a unique firebase_uid (simple UUID-like string for demo)
      const firebase_uid = `uid-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

      await connection.execute(
        'INSERT INTO gym_users (firebase_uid, name, Phone, Address, DOB, member_since, is_admin) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [firebase_uid, name || null, Phone || null, Address || null, DOB || null, member_since || new Date().toISOString().slice(0, 10), is_admin ? 1 : 0]
      );

      res.status(201).json({
        success: true,
        message: 'User created successfully',
        data: {
          firebase_uid: firebase_uid
        }
      });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({
      success: false,
      message: 'Error creating user',
      error: error.message
    });
  }
});

// PUT - Update user admin status (Super Admin only)
app.put('/api/admin/users/:firebase_uid/admin-status', verifyFirebaseToken, verifyAdminToken, async (req, res) => {
  try {
    const { firebase_uid } = req.params;
    const { is_admin } = req.body;

    if (typeof is_admin !== 'boolean') {
      return res.status(400).json({
        success: false,
        message: 'is_admin must be a boolean value'
      });
    }

    // Prevent self-demotion
    if (firebase_uid === req.user.uid && !is_admin) {
      return res.status(400).json({
        success: false,
        message: 'Cannot remove admin privileges from yourself'
      });
    }

    const connection = await pool.getConnection();
    try {
      // Check if user exists
      const [existingUser] = await connection.execute(
        'SELECT firebase_uid FROM gym_users WHERE firebase_uid = ?',
        [firebase_uid]
      );

      if (existingUser.length === 0) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      await connection.execute(
        'UPDATE gym_users SET is_admin = ? WHERE firebase_uid = ?',
        [is_admin ? 1 : 0, firebase_uid]
      );

      res.json({
        success: true,
        message: `User admin status updated to ${is_admin ? 'admin' : 'regular user'}`
      });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error updating admin status:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating admin status',
      error: error.message
    });
  }
});

// ==================== GYM BILLS MANAGEMENT ROUTES ====================

// GET all bills or filter by firebase_uid/status (Protected route)
app.get('/api/gym-bills', verifyFirebaseToken, async (req, res) => {
  try {
    const { firebase_uid, status, month } = req.query;
    let query = 'SELECT * FROM gym_bills WHERE 1=1';
    const params = [];

    // Check if user is admin
    const currentUserUid = req.user.uid;
    const [adminCheck] = await pool.execute(
      'SELECT is_admin FROM gym_users WHERE firebase_uid = ?',
      [currentUserUid]
    );
    
    const isAdmin = adminCheck.length > 0 && adminCheck[0].is_admin;

    // If not admin, only show current user's bills
    if (!isAdmin) {
      query += ' AND firebase_uid = ?';
      params.push(currentUserUid);
    } else if (firebase_uid) {
      query += ' AND firebase_uid = ?';
      params.push(firebase_uid);
    }

    if (status) {
      query += ' AND status = ?';
      params.push(status);
    }

    if (month) {
      query += ' AND DATE_FORMAT(month, "%Y-%m") = ?';
      params.push(month);
    }

    query += ' ORDER BY month DESC, created_at DESC';

    const [rows] = await pool.execute(query, params);
    
    res.json({
      success: true,
      data: rows,
      count: rows.length
    });
  } catch (error) {
    console.error('Error fetching gym bills:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching gym bills',
      error: error.message
    });
  }
});

// GET all bills for admin
app.get('/api/admin/gym-bills', verifyFirebaseToken, verifyAdminToken, async (req, res) => {
  try {
    const { firebase_uid, status, month } = req.query;
    let query = 'SELECT * FROM gym_bills WHERE 1=1';
    const params = [];

    if (firebase_uid) {
      query += ' AND firebase_uid = ?';
      params.push(firebase_uid);
    }

    if (status) {
      query += ' AND status = ?';
      params.push(status);
    }

    if (month) {
      query += ' AND DATE_FORMAT(month, "%Y-%m") = ?';
      params.push(month);
    }

    query += ' ORDER BY month DESC, created_at DESC';

    const [rows] = await pool.execute(query, params);
    
    res.json({
      success: true,
      data: rows,
      count: rows.length
    });
  } catch (error) {
    console.error('Error fetching gym bills:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching gym bills',
      error: error.message
    });
  }
});

// GET single bill by ID (Protected route)
app.get('/api/gym-bills/:id', verifyFirebaseToken, async (req, res) => {
  try {
    const { id } = req.params;
    const currentUserUid = req.user.uid;
    
    // Check if user is admin
    const [adminCheck] = await pool.execute(
      'SELECT is_admin FROM gym_users WHERE firebase_uid = ?',
      [currentUserUid]
    );
    
    const isAdmin = adminCheck.length > 0 && adminCheck[0].is_admin;
    
    let query = 'SELECT * FROM gym_bills WHERE id = ?';
    const params = [id];
    
    // If not admin, only show own bills
    if (!isAdmin) {
      query += ' AND firebase_uid = ?';
      params.push(currentUserUid);
    }
    
    const [rows] = await pool.execute(query, params);

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Bill not found or access denied'
      });
    }

    res.json({
      success: true,
      data: rows[0]
    });
  } catch (error) {
    console.error('Error fetching bill:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching bill',
      error: error.message
    });
  }
});

// POST - Create new bill (Admin only)
app.post('/api/gym-bills', verifyFirebaseToken, verifyAdminToken, async (req, res) => {
  try {
    const { firebase_uid, amount, month, status = 'pending' } = req.body;

    // Validation
    if (!firebase_uid || !amount || !month) {
      return res.status(400).json({
        success: false,
        message: 'firebase_uid, amount, and month are required'
      });
    }

    // Validate status
    if (!['pending', 'paid'].includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Status must be either "pending" or "paid"'
      });
    }

    // Format month for MySQL
    const formattedMonth = formatDateForMySQL(month);

    const [result] = await pool.execute(
      `INSERT INTO gym_bills (firebase_uid, amount, month, status) 
       VALUES (?, ?, ?, ?)`,
      [firebase_uid, amount, formattedMonth, status]
    );

    // Fetch the created bill
    const [newBill] = await pool.execute(
      'SELECT * FROM gym_bills WHERE id = ?',
      [result.insertId]
    );

    res.status(201).json({
      success: true,
      message: 'Bill created successfully',
      data: newBill[0]
    });
  } catch (error) {
    console.error('Error creating bill:', error);
    
    // Handle duplicate entry error
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({
        success: false,
        message: 'Bill already exists for this user and month'
      });
    }

    // Handle foreign key constraint error
    if (error.code === 'ER_NO_REFERENCED_ROW_2') {
      return res.status(400).json({
        success: false,
        message: 'Invalid firebase_uid - user does not exist'
      });
    }

    res.status(500).json({
      success: false,
      message: 'Error creating bill',
      error: error.message
    });
  }
});

// PUT - Update existing bill (Admin or user-owned)
app.put('/api/gym-bills/:id', verifyFirebaseToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { amount, month, status } = req.body;
    const currentUserUid = req.user.uid;

    // Check if bill exists
    const [existingBill] = await pool.execute(
      'SELECT * FROM gym_bills WHERE id = ?',
      [id]
    );

    if (existingBill.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Bill not found'
      });
    }

    // Check if user is admin
    const [adminCheck] = await pool.execute(
      'SELECT is_admin FROM gym_users WHERE firebase_uid = ?',
      [currentUserUid]
    );
    
    const isAdmin = adminCheck.length > 0 && adminCheck[0].is_admin;

    // Users can only update their own bills, admins can update any
    if (!isAdmin && existingBill[0].firebase_uid !== currentUserUid) {
      return res.status(403).json({
        success: false,
        message: 'Access denied: You can only update your own bills'
      });
    }

    // Build dynamic update query
    const updates = [];
    const params = [];

    if (amount !== undefined) {
      updates.push('amount = ?');
      params.push(amount);
    }

    if (month !== undefined) {
      updates.push('month = ?');
      params.push(formatDateForMySQL(month));
    }

    if (status !== undefined) {
      if (!['pending', 'paid'].includes(status)) {
        return res.status(400).json({
          success: false,
          message: 'Status must be either "pending" or "paid"'
        });
      }
      updates.push('status = ?');
      params.push(status);
    }

    if (updates.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No valid fields to update'
      });
    }

    params.push(id);

    await pool.execute(
      `UPDATE gym_bills SET ${updates.join(', ')} WHERE id = ?`,
      params
    );

    // Fetch updated bill
    const [updatedBill] = await pool.execute(
      'SELECT * FROM gym_bills WHERE id = ?',
      [id]
    );

    res.json({
      success: true,
      message: 'Bill updated successfully',
      data: updatedBill[0]
    });
  } catch (error) {
    console.error('Error updating bill:', error);

    // Handle duplicate entry error
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({
        success: false,
        message: 'Bill already exists for this user and month'
      });
    }

    res.status(500).json({
      success: false,
      message: 'Error updating bill',
      error: error.message
    });
  }
});

// DELETE - Delete bill (Admin only)
app.delete('/api/gym-bills/:id', verifyFirebaseToken, verifyAdminToken, async (req, res) => {
  try {
    const { id } = req.params;

    // Check if bill exists
    const [existingBill] = await pool.execute(
      'SELECT * FROM gym_bills WHERE id = ?',
      [id]
    );

    if (existingBill.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Bill not found'
      });
    }

    await pool.execute('DELETE FROM gym_bills WHERE id = ?', [id]);

    res.json({
      success: true,
      message: 'Bill deleted successfully',
      data: existingBill[0]
    });
  } catch (error) {
    console.error('Error deleting bill:', error);
    res.status(500).json({
      success: false,
      message: 'Error deleting bill',
      error: error.message
    });
  }
});

// ==================== GYM PLANS MANAGEMENT ROUTES ====================

// GET all plans or filter by firebase_uid/status (Protected route)
app.get('/api/gym-plans', verifyFirebaseToken, async (req, res) => {
  try {
    const { firebase_uid, status, active_only } = req.query;
    let query = 'SELECT * FROM gym_plans WHERE 1=1';
    const params = [];

    // Check if user is admin
    const currentUserUid = req.user.uid;
    const [adminCheck] = await pool.execute(
      'SELECT is_admin FROM gym_users WHERE firebase_uid = ?',
      [currentUserUid]
    );
    
    const isAdmin = adminCheck.length > 0 && adminCheck[0].is_admin;

    // If not admin, only show current user's plans
    if (!isAdmin) {
      query += ' AND firebase_uid = ?';
      params.push(currentUserUid);
    } else if (firebase_uid) {
      query += ' AND firebase_uid = ?';
      params.push(firebase_uid);
    }

    if (status) {
      query += ' AND status = ?';
      params.push(status);
    }

    if (active_only === 'true') {
      query += ' AND end_date >= CURDATE() AND status = "Active"';
    }

    query += ' ORDER BY created_at DESC, start_date DESC';

    const [rows] = await pool.execute(query, params);
    
    res.json({
      success: true,
      data: rows,
      count: rows.length
    });
  } catch (error) {
    console.error('Error fetching gym plans:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching gym plans',
      error: error.message
    });
  }
});

// GET all plans for admin
app.get('/api/admin/gym-plans', verifyFirebaseToken, verifyAdminToken, async (req, res) => {
  try {
    const { firebase_uid, status, active_only } = req.query;
    let query = 'SELECT * FROM gym_plans WHERE 1=1';
    const params = [];

    if (firebase_uid) {
      query += ' AND firebase_uid = ?';
      params.push(firebase_uid);
    }

    if (status) {
      query += ' AND status = ?';
      params.push(status);
    }

    if (active_only === 'true') {
      query += ' AND end_date >= CURDATE() AND status = "Active"';
    }

    query += ' ORDER BY created_at DESC, start_date DESC';

    const [rows] = await pool.execute(query, params);

    // Add user data to plans
    const plansWithUsers = await Promise.all(
      rows.map(async (plan) => {
        try {
          const [user] = await pool.execute(
            'SELECT firebase_uid AS user_id, name, Phone, Address FROM gym_users WHERE firebase_uid = ?',
            [plan.firebase_uid]
          );
          const firebaseUser = await admin.auth().getUser(plan.firebase_uid).catch(() => null);
          return {
            ...plan,
            user_id: plan.firebase_uid,
            user_name: user.length > 0 ? (user[0].name || firebaseUser?.displayName || user[0].Phone || user[0].Address || user[0].user_id) : (firebaseUser?.displayName || 'Unknown User'),
            user_email: firebaseUser?.email || null
          };
        } catch (error) {
          console.warn(`Error fetching user data for plan ${plan.id}:`, error);
          return {
            ...plan,
            user_id: plan.firebase_uid,
            user_name: 'Unknown User',
            user_email: null
          };
        }
      })
    );

    res.json({
      success: true,
      data: plansWithUsers,
      count: plansWithUsers.length
    });
  } catch (error) {
    console.error('Error fetching gym plans:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching gym plans',
      error: error.message
    });
  }
});

// GET single plan by ID (Protected route)
app.get('/api/gym-plans/:id', verifyFirebaseToken, async (req, res) => {
  try {
    const { id } = req.params;
    const currentUserUid = req.user.uid;
    
    // Check if user is admin
    const [adminCheck] = await pool.execute(
      'SELECT is_admin FROM gym_users WHERE firebase_uid = ?',
      [currentUserUid]
    );
    
    const isAdmin = adminCheck.length > 0 && adminCheck[0].is_admin;
    
    let query = 'SELECT * FROM gym_plans WHERE id = ?';
    const params = [id];
    
    // If not admin, only show own plans
    if (!isAdmin) {
      query += ' AND firebase_uid = ?';
      params.push(currentUserUid);
    }
    
    const [rows] = await pool.execute(query, params);

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Plan not found or access denied'
      });
    }

    res.json({
      success: true,
      data: rows[0]
    });
  } catch (error) {
    console.error('Error fetching plan:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching plan',
      error: error.message
    });
  }
});

// POST - Create new plan (Admin or user-owned)
app.post('/api/gym-plans', verifyFirebaseToken, async (req, res) => {
  try {
    const { firebase_uid, plan, start_date, end_date, status = 'Active' } = req.body;
    const currentUserUid = req.user.uid;

    // Validation
    if (!firebase_uid || !plan || !start_date || !end_date) {
      return res.status(400).json({
        success: false,
        message: 'firebase_uid, plan, start_date, and end_date are required'
      });
    }

    // Check if user is admin
    const [adminCheck] = await pool.execute(
      'SELECT is_admin FROM gym_users WHERE firebase_uid = ?',
      [currentUserUid]
    );
    
    const isAdmin = adminCheck.length > 0 && adminCheck[0].is_admin;

    // Users can only create plans for themselves, admins can create for anyone
    if (!isAdmin && firebase_uid !== currentUserUid) {
      return res.status(403).json({
        success: false,
        message: 'Access denied: You can only create plans for yourself'
      });
    }

    // Validate status
    if (!['Active', 'Inactive'].includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Status must be either "Active" or "Inactive"'
      });
    }

    // Validate date formats
    if (!isValidDate(start_date) || !isValidDate(end_date)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid date format. Use YYYY-MM-DD format'
      });
    }

    // Check if end_date is after start_date
    if (new Date(end_date) <= new Date(start_date)) {
      return res.status(400).json({
        success: false,
        message: 'End date must be after start date'
      });
    }

    const [result] = await pool.execute(
      `INSERT INTO gym_plans (firebase_uid, plan, start_date, end_date, status) 
       VALUES (?, ?, ?, ?, ?)`,
      [firebase_uid, plan, start_date, end_date, status]
    );

    // Fetch the created plan
    const [newPlan] = await pool.execute(
      'SELECT * FROM gym_plans WHERE id = ?',
      [result.insertId]
    );

    res.status(201).json({
      success: true,
      message: 'Gym plan created successfully',
      data: newPlan[0]
    });
  } catch (error) {
    console.error('Error creating gym plan:', error);
    
    // Handle foreign key constraint error
    if (error.code === 'ER_NO_REFERENCED_ROW_2') {
      return res.status(400).json({
        success: false,
        message: 'Invalid firebase_uid - user does not exist'
      });
    }

    res.status(500).json({
      success: false,
      message: 'Error creating gym plan',
      error: error.message
    });
  }
});

// PUT - Update existing plan (Admin or user-owned)
app.put('/api/gym-plans/:id', verifyFirebaseToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { plan, start_date, end_date, status } = req.body;
    const currentUserUid = req.user.uid;

    // Check if plan exists
    const [existingPlan] = await pool.execute(
      'SELECT * FROM gym_plans WHERE id = ?',
      [id]
    );

    if (existingPlan.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Plan not found'
      });
    }

    // Check if user is admin
    const [adminCheck] = await pool.execute(
      'SELECT is_admin FROM gym_users WHERE firebase_uid = ?',
      [currentUserUid]
    );
    
    const isAdmin = adminCheck.length > 0 && adminCheck[0].is_admin;

    // Users can only update their own plans, admins can update any
    if (!isAdmin && existingPlan[0].firebase_uid !== currentUserUid) {
      return res.status(403).json({
        success: false,
        message: 'Access denied: You can only update your own plans'
      });
    }

    // Build dynamic update query
    const updates = [];
    const params = [];

    if (plan !== undefined) {
      updates.push('plan = ?');
      params.push(plan);
    }

    if (start_date !== undefined) {
      if (!isValidDate(start_date)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid start_date format. Use YYYY-MM-DD format'
        });
      }
      updates.push('start_date = ?');
      params.push(start_date);
    }

    if (end_date !== undefined) {
      if (!isValidDate(end_date)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid end_date format. Use YYYY-MM-DD format'
        });
      }
      updates.push('end_date = ?');
      params.push(end_date);
    }

    if (status !== undefined) {
      if (!['Active', 'Inactive'].includes(status)) {
        return res.status(400).json({
          success: false,
          message: 'Status must be either "Active" or "Inactive"'
        });
      }
      updates.push('status = ?');
      params.push(status);
    }

    if (updates.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No valid fields to update'
      });
    }

    // Additional validation if both dates are being updated or if one is updated
    const finalStartDate = start_date || existingPlan[0].start_date;
    const finalEndDate = end_date || existingPlan[0].end_date;
    
    if (new Date(finalEndDate) <= new Date(finalStartDate)) {
      return res.status(400).json({
        success: false,
        message: 'End date must be after start date'
      });
    }

    params.push(id);

    await pool.execute(
      `UPDATE gym_plans SET ${updates.join(', ')} WHERE id = ?`,
      params
    );

    // Fetch updated plan
    const [updatedPlan] = await pool.execute(
      'SELECT * FROM gym_plans WHERE id = ?',
      [id]
    );

    res.json({
      success: true,
      message: 'Gym plan updated successfully',
      data: updatedPlan[0]
    });
  } catch (error) {
    console.error('Error updating gym plan:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating gym plan',
      error: error.message
    });
  }
});

// DELETE - Delete plan (Admin or user-owned)
app.delete('/api/gym-plans/:id', verifyFirebaseToken, async (req, res) => {
  try {
    const { id } = req.params;
    const currentUserUid = req.user.uid;

    // Check if plan exists
    const [existingPlan] = await pool.execute(
      'SELECT * FROM gym_plans WHERE id = ?',
      [id]
    );

    if (existingPlan.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Plan not found'
      });
    }

    // Check if user is admin
    const [adminCheck] = await pool.execute(
      'SELECT is_admin FROM gym_users WHERE firebase_uid = ?',
      [currentUserUid]
    );
    
    const isAdmin = adminCheck.length > 0 && adminCheck[0].is_admin;

    // Users can only delete their own plans, admins can delete any
    if (!isAdmin && existingPlan[0].firebase_uid !== currentUserUid) {
      return res.status(403).json({
        success: false,
        message: 'Access denied: You can only delete your own plans'
      });
    }

    await pool.execute('DELETE FROM gym_plans WHERE id = ?', [id]);

    res.json({
      success: true,
      message: 'Gym plan deleted successfully',
      data: existingPlan[0]
    });
  } catch (error) {
    console.error('Error deleting gym plan:', error);
    res.status(500).json({
      success: false,
      message: 'Error deleting gym plan',
      error: error.message
    });
  }
});

// GET user's active/current plans
app.get('/api/gym-plans/active/current', verifyFirebaseToken, async (req, res) => {
  try {
    const currentUserUid = req.user.uid;
    
    const [rows] = await pool.execute(
      `SELECT * FROM gym_plans 
       WHERE firebase_uid = ? 
       AND status = 'Active' 
       AND start_date <= CURDATE() 
       AND end_date >= CURDATE()
       ORDER BY start_date DESC`,
      [currentUserUid]
    );

    res.json({
      success: true,
      data: rows,
      count: rows.length,
      message: rows.length > 0 ? 'Active plans found' : 'No active plans found'
    });
  } catch (error) {
    console.error('Error fetching active gym plans:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching active gym plans',
      error: error.message
    });
  }
});

// GET plans expiring soon (within next 30 days)
app.get('/api/gym-plans/expiring-soon', verifyFirebaseToken, async (req, res) => {
  try {
    const currentUserUid = req.user.uid;
    const { days = 30 } = req.query;
    
    const [rows] = await pool.execute(
      `SELECT * FROM gym_plans 
       WHERE firebase_uid = ? 
       AND status = 'Active' 
       AND end_date >= CURDATE() 
       AND end_date <= DATE_ADD(CURDATE(), INTERVAL ? DAY)
       ORDER BY end_date ASC`,
      [currentUserUid, parseInt(days)]
    );

    res.json({
      success: true,
      data: rows,
      count: rows.length,
      message: `Plans expiring within ${days} days`
    });
  } catch (error) {
    console.error('Error fetching expiring gym plans:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching expiring gym plans',
      error: error.message
    });
  }
});

// GET admin endpoint for plans expiring soon (all users)
app.get('/api/admin/gym-plans/expiring-soon', verifyFirebaseToken, verifyAdminToken, async (req, res) => {
  try {
    const { days = 30 } = req.query;
    
    const [rows] = await pool.execute(
      `SELECT gp.*, gu.name, gu.Phone, gu.Address 
       FROM gym_plans gp
       LEFT JOIN gym_users gu ON gp.firebase_uid = gu.firebase_uid
       WHERE gp.status = 'Active' 
       AND gp.end_date >= CURDATE() 
       AND gp.end_date <= DATE_ADD(CURDATE(), INTERVAL ? DAY)
       ORDER BY gp.end_date ASC`,
      [parseInt(days)]
    );

    // Add user data
    const plansWithUsers = await Promise.all(
      rows.map(async (plan) => {
        try {
          const firebaseUser = await admin.auth().getUser(plan.firebase_uid).catch(() => null);
          return {
            ...plan,
            user_id: plan.firebase_uid,
            user_name: plan.name || firebaseUser?.displayName || plan.Phone || plan.Address || plan.firebase_uid || 'Unknown User',
            user_email: firebaseUser?.email || null
          };
        } catch (error) {
          console.warn(`Error fetching user data for plan ${plan.id}:`, error);
          return {
            ...plan,
            user_id: plan.firebase_uid,
            user_name: plan.name || plan.Phone || plan.Address || plan.firebase_uid || 'Unknown User',
            user_email: null
          };
        }
      })
    );

    res.json({
      success: true,
      data: plansWithUsers,
      count: plansWithUsers.length,
      message: `Plans expiring within ${days} days`
    });
  } catch (error) {
    console.error('Error fetching expiring gym plans:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching expiring gym plans',
      error: error.message
    });
  }
});

// PATCH - Update plan status only
app.patch('/api/gym-plans/:id/status', verifyFirebaseToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    const currentUserUid = req.user.uid;

    if (!status || !['Active', 'Inactive'].includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Valid status is required (Active or Inactive)'
      });
    }

    // Check if plan exists
    const [existingPlan] = await pool.execute(
      'SELECT * FROM gym_plans WHERE id = ?',
      [id]
    );

    if (existingPlan.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Plan not found'
      });
    }

    // Check if user is admin
    const [adminCheck] = await pool.execute(
      'SELECT is_admin FROM gym_users WHERE firebase_uid = ?',
      [currentUserUid]
    );
    
    const isAdmin = adminCheck.length > 0 && adminCheck[0].is_admin;

    // Users can only update their own plans, admins can update any
    if (!isAdmin && existingPlan[0].firebase_uid !== currentUserUid) {
      return res.status(403).json({
        success: false,
        message: 'Plan not found or access denied'
      });
    }

    await pool.execute(
      'UPDATE gym_plans SET status = ? WHERE id = ?',
      [status, id]
    );

    // Fetch updated plan
    const [updatedPlan] = await pool.execute(
      'SELECT * FROM gym_plans WHERE id = ?',
      [id]
    );

    res.json({
      success: true,
      message: `Plan status updated to ${status}`,
      data: updatedPlan[0]
    });
  } catch (error) {
    console.error('Error updating plan status:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating plan status',
      error: error.message
    });
  }
});

// ==================== COMBINED ENDPOINTS (USER DASHBOARD DATA) ====================

// GET user dashboard data (combines user profile, active plans, pending bills)
app.get('/api/dashboard', verifyFirebaseToken, async (req, res) => {
  try {
    const firebase_uid = req.user.uid;
    const connection = await pool.getConnection();
    
    try {
      // Get user profile data
      const firebaseUser = await admin.auth().getUser(firebase_uid);
      const firebaseData = {
        name: firebaseUser.displayName || null,
        email: firebaseUser.email || null,
        firebase_uid: firebaseUser.uid,
        email_verified: firebaseUser.emailVerified,
        photo_url: firebaseUser.photoURL || null
      };

      // Get database user data
      const [userData] = await connection.execute(
        'SELECT name, Phone, Address, DOB, member_since, is_admin FROM gym_users WHERE firebase_uid = ?',
        [firebase_uid]
      );

      // Get active plans
      const [activePlans] = await connection.execute(
        `SELECT * FROM gym_plans 
         WHERE firebase_uid = ? 
         AND status = 'Active' 
         AND start_date <= CURDATE() 
         AND end_date >= CURDATE()
         ORDER BY start_date DESC`,
        [firebase_uid]
      );

      // Get pending bills
      const [pendingBills] = await connection.execute(
        `SELECT * FROM gym_bills 
         WHERE firebase_uid = ? 
         AND status = 'pending'
         ORDER BY month DESC`,
        [firebase_uid]
      );

      // Get plans expiring in next 30 days
      const [expiringPlans] = await connection.execute(
        `SELECT * FROM gym_plans 
         WHERE firebase_uid = ? 
         AND status = 'Active' 
         AND end_date >= CURDATE() 
         AND end_date <= DATE_ADD(CURDATE(), INTERVAL 30 DAY)
         ORDER BY end_date ASC`,
        [firebase_uid]
      );

      // Get recent activity (last 5 bills)
      const [recentBills] = await connection.execute(
        `SELECT * FROM gym_bills 
         WHERE firebase_uid = ? 
         ORDER BY created_at DESC 
         LIMIT 5`,
        [firebase_uid]
      );

      const userProfile = {
        ...firebaseData,
        name: userData.length > 0 ? (userData[0].name || firebaseData.name) : firebaseData.name,
        ...(userData.length > 0 ? {
          Phone: userData[0].Phone,
          Address: userData[0].Address,
          DOB: userData[0].DOB,
          member_since: userData[0].member_since,
          is_admin: Boolean(userData[0].is_admin)
        } : {
          Phone: null,
          Address: null,
          DOB: null,
          member_since: null,
          is_admin: false
        })
      };

      const dashboardData = {
        user_profile: userProfile,
        active_plans: activePlans,
        pending_bills: pendingBills,
        expiring_plans: expiringPlans,
        recent_bills: recentBills,
        summary: {
          active_plans_count: activePlans.length,
          pending_bills_count: pendingBills.length,
          total_pending_amount: pendingBills.reduce((sum, bill) => sum + parseFloat(bill.amount), 0),
          expiring_plans_count: expiringPlans.length
        }
      };

      res.json({
        success: true,
        data: dashboardData
      });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error fetching dashboard data:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching dashboard data',
      error: error.message
    });
  }
});

// GET admin dashboard data (Admin only)
app.get('/api/admin/dashboard', verifyFirebaseToken, verifyAdminToken, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    
    try {
      // Get total users count
      const [totalUsers] = await connection.execute(
        'SELECT COUNT(*) as count FROM gym_users'
      );

      // Get total active plans
      const [activePlans] = await connection.execute(
        `SELECT COUNT(*) as count FROM gym_plans 
         WHERE status = 'Active' 
         AND start_date <= CURDATE() 
         AND end_date >= CURDATE()`
      );

      // Get total pending bills
      const [pendingBills] = await connection.execute(
        `SELECT COUNT(*) as count, COALESCE(SUM(amount), 0) as total_amount 
         FROM gym_bills 
         WHERE status = 'pending'`
      );

      // Get plans expiring in next 30 days
      const [expiringPlans] = await connection.execute(
        `SELECT COUNT(*) as count FROM gym_plans 
         WHERE status = 'Active' 
         AND end_date >= CURDATE() 
         AND end_date <= DATE_ADD(CURDATE(), INTERVAL 30 DAY)`
      );

      // Get recent activities (last 10 bills and plans)
      const [recentBills] = await connection.execute(
        `SELECT gb.*, gu.name, gu.Phone 
         FROM gym_bills gb
         LEFT JOIN gym_users gu ON gb.firebase_uid = gu.firebase_uid
         ORDER BY gb.created_at DESC 
         LIMIT 10`
      );

      const [recentPlans] = await connection.execute(
        `SELECT gp.*, gu.name, gu.Phone 
         FROM gym_plans gp
         LEFT JOIN gym_users gu ON gp.firebase_uid = gu.firebase_uid
         ORDER BY gp.created_at DESC 
         LIMIT 10`
      );

      // Get monthly revenue data (last 6 months)
      const [monthlyRevenue] = await connection.execute(
        `SELECT 
           DATE_FORMAT(month, '%Y-%m') as month,
           SUM(CASE WHEN status = 'paid' THEN amount ELSE 0 END) as paid_amount,
           SUM(CASE WHEN status = 'pending' THEN amount ELSE 0 END) as pending_amount,
           COUNT(*) as total_bills
         FROM gym_bills 
         WHERE month >= DATE_SUB(CURDATE(), INTERVAL 6 MONTH)
         GROUP BY DATE_FORMAT(month, '%Y-%m')
         ORDER BY month DESC`
      );

      const adminDashboard = {
        summary: {
          total_users: totalUsers[0].count,
          active_plans: activePlans[0].count,
          pending_bills_count: pendingBills[0].count,
          pending_bills_amount: pendingBills[0].total_amount,
          expiring_plans: expiringPlans[0].count
        },
        recent_bills: recentBills,
        recent_plans: recentPlans,
        monthly_revenue: monthlyRevenue
      };

      res.json({
        success: true,
        data: adminDashboard
      });
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error fetching admin dashboard data:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching admin dashboard data',
      error: error.message
    });
  }
});

// ==================== HEALTH CHECK & GENERAL ROUTES ====================

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    success: true, 
    message: 'Server is running',
    timestamp: new Date().toISOString()
  });
});

// Public health check
app.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'Server is running',
    timestamp: new Date().toISOString()
  });
});

// API Documentation endpoint
app.get('/api/docs', (req, res) => {
  const apiDocs = {
    success: true,
    message: 'Gym Management API Documentation',
    version: '1.0.0',
    endpoints: {
      authentication: {
        description: 'All protected endpoints require Bearer token in Authorization header',
        header: 'Authorization: Bearer <firebase_token>',
        admin_note: 'Admin endpoints require user to have is_admin=1 in database'
      },
      user_management: {
        'GET /api/user/profile': 'Get current user profile',
        'PUT /api/user/profile': 'Update user profile',
        'GET /api/users': 'Get all users (admin only)',
        'POST /api/admin/users': 'Create new user (admin only)',
        'PUT /api/admin/users/:firebase_uid/admin-status': 'Update user admin status (admin only)'
      },
      gym_bills: {
        'GET /api/gym-bills': 'Get user bills (admins see all, users see own)',
        'GET /api/gym-bills/:id': 'Get specific bill',
        'POST /api/gym-bills': 'Create new bill (admin only)',
        'PUT /api/gym-bills/:id': 'Update bill (admin or owner)',
        'DELETE /api/gym-bills/:id': 'Delete bill (admin only)',
        'GET /api/admin/gym-bills': 'Get all bills (admin only)'
      },
      gym_plans: {
        'GET /api/gym-plans': 'Get user plans (admins see all, users see own)',
        'GET /api/gym-plans/:id': 'Get specific plan',
        'POST /api/gym-plans': 'Create new plan (admin can create for anyone, users for self)',
        'PUT /api/gym-plans/:id': 'Update plan (admin or owner)',
        'DELETE /api/gym-plans/:id': 'Delete plan (admin or owner)',
        'PATCH /api/gym-plans/:id/status': 'Update plan status only',
        'GET /api/gym-plans/active/current': 'Get currently active plans',
        'GET /api/gym-plans/expiring-soon': 'Get plans expiring soon',
        'GET /api/admin/gym-plans': 'Get all plans (admin only)',
        'GET /api/admin/gym-plans/expiring-soon': 'Get all expiring plans (admin only)'
      },
      dashboard: {
        'GET /api/dashboard': 'Get user dashboard data',
        'GET /api/admin/dashboard': 'Get admin dashboard data (admin only)'
      },
      health: {
        'GET /health': 'Public health check',
        'GET /api/health': 'API health check'
      }
    },
    query_parameters: {
      gym_bills: ['firebase_uid', 'status', 'month'],
      gym_plans: ['firebase_uid', 'status', 'active_only'],
      expiring_plans: ['days (default: 30)']
    },
    admin_features: {
      description: 'Admin users (is_admin=1) have additional privileges',
      privileges: [
        'View all users, bills, and plans',
        'Create bills and users',
        'Delete bills',
        'Update admin status of other users',
        'Access admin dashboard with statistics'
      ]
    }
  };
  
  res.json(apiDocs);
});
// ==================== FINGERPRINT MANAGEMENT ROUTES ====================

// GET all fingerprints (Admin only)
app.get('/api/fingerprints', verifyFirebaseToken, verifyAdminToken, async (req, res) => {
  try {
    const { firebase_uid } = req.query;
    let query = `SELECT f.*, u.name, u.Phone, u.Address 
                 FROM gym_fingerprints f
                 LEFT JOIN gym_users u ON f.firebase_uid = u.firebase_uid
                 WHERE 1=1`;
    const params = [];

    if (firebase_uid) {
      query += ' AND f.firebase_uid = ?';
      params.push(firebase_uid);
    }

    query += ' ORDER BY f.enrolled_at DESC';

    const [rows] = await pool.execute(query, params);
    
    // Add user email from Firebase
    const fingerprintsWithUserData = await Promise.all(
      rows.map(async (fp) => {
        try {
          const firebaseUser = await admin.auth().getUser(fp.firebase_uid).catch(() => null);
          return {
            ...fp,
            user_name: fp.name || firebaseUser?.displayName || 'Unknown User',
            user_email: firebaseUser?.email || null
          };
        } catch (error) {
          return {
            ...fp,
            user_name: fp.name || 'Unknown User',
            user_email: null
          };
        }
      })
    );

    res.json({
      success: true,
      data: fingerprintsWithUserData,
      count: fingerprintsWithUserData.length
    });
  } catch (error) {
    console.error('Error fetching fingerprints:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching fingerprints',
      error: error.message
    });
  }
});

// GET user's own fingerprints
app.get('/api/user/fingerprints', verifyFirebaseToken, async (req, res) => {
  try {
    const firebase_uid = req.user.uid;
    
    const [rows] = await pool.execute(
      'SELECT * FROM gym_fingerprints WHERE firebase_uid = ? ORDER BY enrolled_at DESC',
      [firebase_uid]
    );

    res.json({
      success: true,
      data: rows,
      count: rows.length
    });
  } catch (error) {
    console.error('Error fetching user fingerprints:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching fingerprints',
      error: error.message
    });
  }
});

// POST - Enroll new fingerprint
app.post('/api/fingerprints', verifyFirebaseToken, async (req, res) => {
  try {
    const { firebase_uid, fingerprint_template, fingerprint_id, finger_name } = req.body;
    const currentUserUid = req.user.uid;

    // Validation
    if (!firebase_uid || !fingerprint_template || !fingerprint_id) {
      return res.status(400).json({
        success: false,
        message: 'firebase_uid, fingerprint_template, and fingerprint_id are required'
      });
    }

    // Check if user is admin
    const [adminCheck] = await pool.execute(
      'SELECT is_admin FROM gym_users WHERE firebase_uid = ?',
      [currentUserUid]
    );
    
    const isAdmin = adminCheck.length > 0 && adminCheck[0].is_admin;

    // Users can only enroll for themselves, admins can enroll for anyone
    if (!isAdmin && firebase_uid !== currentUserUid) {
      return res.status(403).json({
        success: false,
        message: 'Access denied: You can only enroll fingerprints for yourself'
      });
    }

    // Check if fingerprint_id already exists
    const [existingFingerprint] = await pool.execute(
      'SELECT id FROM gym_fingerprints WHERE fingerprint_id = ?',
      [fingerprint_id]
    );

    if (existingFingerprint.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'Fingerprint ID already exists'
      });
    }

    // Insert new fingerprint
    const [result] = await pool.execute(
      `INSERT INTO gym_fingerprints 
       (firebase_uid, fingerprint_template, fingerprint_id, finger_name, is_active) 
       VALUES (?, ?, ?, ?, 1)`,
      [firebase_uid, fingerprint_template, fingerprint_id, finger_name || 'Default']
    );

    // Fetch the created fingerprint
    const [newFingerprint] = await pool.execute(
      'SELECT * FROM gym_fingerprints WHERE id = ?',
      [result.insertId]
    );

    res.status(201).json({
      success: true,
      message: 'Fingerprint enrolled successfully',
      data: newFingerprint[0]
    });
  } catch (error) {
    console.error('Error enrolling fingerprint:', error);
    
    if (error.code === 'ER_NO_REFERENCED_ROW_2') {
      return res.status(400).json({
        success: false,
        message: 'Invalid firebase_uid - user does not exist'
      });
    }

    res.status(500).json({
      success: false,
      message: 'Error enrolling fingerprint',
      error: error.message
    });
  }
});

// PUT - Update fingerprint
app.put('/api/fingerprints/:id', verifyFirebaseToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { fingerprint_template, finger_name, is_active } = req.body;
    const currentUserUid = req.user.uid;

    // Check if fingerprint exists
    const [existingFingerprint] = await pool.execute(
      'SELECT * FROM gym_fingerprints WHERE id = ?',
      [id]
    );

    if (existingFingerprint.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Fingerprint not found'
      });
    }

    // Check if user is admin
    const [adminCheck] = await pool.execute(
      'SELECT is_admin FROM gym_users WHERE firebase_uid = ?',
      [currentUserUid]
    );
    
    const isAdmin = adminCheck.length > 0 && adminCheck[0].is_admin;

    // Users can only update their own fingerprints
    if (!isAdmin && existingFingerprint[0].firebase_uid !== currentUserUid) {
      return res.status(403).json({
        success: false,
        message: 'Access denied: You can only update your own fingerprints'
      });
    }

    // Build dynamic update query
    const updates = [];
    const params = [];

    if (fingerprint_template !== undefined) {
      updates.push('fingerprint_template = ?');
      params.push(fingerprint_template);
    }

    if (finger_name !== undefined) {
      updates.push('finger_name = ?');
      params.push(finger_name);
    }

    if (is_active !== undefined) {
      updates.push('is_active = ?');
      params.push(is_active ? 1 : 0);
    }

    if (updates.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No valid fields to update'
      });
    }

    params.push(id);

    await pool.execute(
      `UPDATE gym_fingerprints SET ${updates.join(', ')} WHERE id = ?`,
      params
    );

    // Fetch updated fingerprint
    const [updatedFingerprint] = await pool.execute(
      'SELECT * FROM gym_fingerprints WHERE id = ?',
      [id]
    );

    res.json({
      success: true,
      message: 'Fingerprint updated successfully',
      data: updatedFingerprint[0]
    });
  } catch (error) {
    console.error('Error updating fingerprint:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating fingerprint',
      error: error.message
    });
  }
});

// DELETE - Delete fingerprint
app.delete('/api/fingerprints/:id', verifyFirebaseToken, async (req, res) => {
  try {
    const { id } = req.params;
    const currentUserUid = req.user.uid;

    // Check if fingerprint exists
    const [existingFingerprint] = await pool.execute(
      'SELECT * FROM gym_fingerprints WHERE id = ?',
      [id]
    );

    if (existingFingerprint.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Fingerprint not found'
      });
    }

    // Check if user is admin
    const [adminCheck] = await pool.execute(
      'SELECT is_admin FROM gym_users WHERE firebase_uid = ?',
      [currentUserUid]
    );
    
    const isAdmin = adminCheck.length > 0 && adminCheck[0].is_admin;

    // Users can only delete their own fingerprints
    if (!isAdmin && existingFingerprint[0].firebase_uid !== currentUserUid) {
      return res.status(403).json({
        success: false,
        message: 'Access denied: You can only delete your own fingerprints'
      });
    }

    await pool.execute('DELETE FROM gym_fingerprints WHERE id = ?', [id]);

    res.json({
      success: true,
      message: 'Fingerprint deleted successfully',
      data: existingFingerprint[0]
    });
  } catch (error) {
    console.error('Error deleting fingerprint:', error);
    res.status(500).json({
      success: false,
      message: 'Error deleting fingerprint',
      error: error.message
    });
  }
});

// POST - Verify fingerprint and log entry
app.post('/api/fingerprints/verify', async (req, res) => {
  try {
    const { fingerprint_id } = req.body;

    if (!fingerprint_id) {
      return res.status(400).json({
        success: false,
        message: 'fingerprint_id is required'
      });
    }

    // Find fingerprint
    const [fingerprints] = await pool.execute(
      `SELECT f.*, u.name, u.Phone 
       FROM gym_fingerprints f
       LEFT JOIN gym_users u ON f.firebase_uid = u.firebase_uid
       WHERE f.fingerprint_id = ? AND f.is_active = 1`,
      [fingerprint_id]
    );

    if (fingerprints.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Fingerprint not found or inactive'
      });
    }

    const fingerprint = fingerprints[0];

    // Check if user has active plan
    const [activePlans] = await pool.execute(
      `SELECT * FROM gym_plans 
       WHERE firebase_uid = ? 
       AND status = 'Active' 
       AND start_date <= CURDATE() 
       AND end_date >= CURDATE()`,
      [fingerprint.firebase_uid]
    );

    const hasActivePlan = activePlans.length > 0;

    // Log entry
    const [result] = await pool.execute(
      `INSERT INTO gym_entries 
       (firebase_uid, fingerprint_id, entry_status, has_active_plan) 
       VALUES (?, ?, ?, ?)`,
      [
        fingerprint.firebase_uid, 
        fingerprint_id, 
        hasActivePlan ? 'allowed' : 'denied',
        hasActivePlan ? 1 : 0
      ]
    );

    // Get entry details
    const [entry] = await pool.execute(
      'SELECT * FROM gym_entries WHERE id = ?',
      [result.insertId]
    );

    res.json({
      success: true,
      message: hasActivePlan ? 'Access granted' : 'Access denied - No active plan',
      data: {
        entry: entry[0],
        user: {
          firebase_uid: fingerprint.firebase_uid,
          name: fingerprint.name,
          phone: fingerprint.Phone
        },
        access_granted: hasActivePlan,
        active_plans: activePlans
      }
    });
  } catch (error) {
    console.error('Error verifying fingerprint:', error);
    res.status(500).json({
      success: false,
      message: 'Error verifying fingerprint',
      error: error.message
    });
  }
});

// GET all entry logs (Admin only)
app.get('/api/entries', verifyFirebaseToken, verifyAdminToken, async (req, res) => {
  try {
    const { firebase_uid, date_from, date_to, status } = req.query;
    let query = `SELECT e.*, u.name, u.Phone, u.Address 
                 FROM gym_entries e
                 LEFT JOIN gym_users u ON e.firebase_uid = u.firebase_uid
                 WHERE 1=1`;
    const params = [];

    if (firebase_uid) {
      query += ' AND e.firebase_uid = ?';
      params.push(firebase_uid);
    }

    if (date_from) {
      query += ' AND DATE(e.entry_time) >= ?';
      params.push(date_from);
    }

    if (date_to) {
      query += ' AND DATE(e.entry_time) <= ?';
      params.push(date_to);
    }

    if (status) {
      query += ' AND e.entry_status = ?';
      params.push(status);
    }

    query += ' ORDER BY e.entry_time DESC LIMIT 1000';

    const [rows] = await pool.execute(query, params);

    res.json({
      success: true,
      data: rows,
      count: rows.length
    });
  } catch (error) {
    console.error('Error fetching entries:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching entries',
      error: error.message
    });
  }
});

// GET user's own entry logs
app.get('/api/user/entries', verifyFirebaseToken, async (req, res) => {
  try {
    const firebase_uid = req.user.uid;
    const { date_from, date_to } = req.query;
    
    let query = 'SELECT * FROM gym_entries WHERE firebase_uid = ?';
    const params = [firebase_uid];

    if (date_from) {
      query += ' AND DATE(entry_time) >= ?';
      params.push(date_from);
    }

    if (date_to) {
      query += ' AND DATE(entry_time) <= ?';
      params.push(date_to);
    }

    query += ' ORDER BY entry_time DESC LIMIT 100';

    const [rows] = await pool.execute(query, params);

    res.json({
      success: true,
      data: rows,
      count: rows.length
    });
  } catch (error) {
    console.error('Error fetching user entries:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching entries',
      error: error.message
    });
  }
});


// ==================== ERROR HANDLING & 404 ====================

// Handle 404
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found',
    suggestion: 'Check /api/docs for available endpoints'
  });
});

// Global error handler
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    error: error.message
  });
});

// ==================== SERVER STARTUP ====================

// Start server
async function startServer() {
  try {
    await testConnection();
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      console.log(`Health check: http://localhost:${PORT}/health`);
      console.log(`API Health check: http://localhost:${PORT}/api/health`);
      console.log(`API Documentation: http://localhost:${PORT}/api/docs`);
      console.log('Admin features enabled - users with is_admin=1 have elevated privileges');
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();

module.exports = app;
