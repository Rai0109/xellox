from flask import Flask, jsonify, render_template, request, send_from_directory, session, redirect
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import sqlite3
import os
import json
import uuid
from functools import wraps

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = "xelloxx_shop_secret_key_2026"
CORS(app)

DB_PATH = "xelloxx_shop.db"

# ==================== DATABASE SETUP ====================
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        is_admin INTEGER DEFAULT 0,
        balance REAL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Products (Bots & Files)
    c.execute('''CREATE TABLE IF NOT EXISTS products (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        type TEXT NOT NULL,
        price REAL NOT NULL,
        category TEXT NOT NULL,
        image_url TEXT,
        file_path TEXT,
        rental_price REAL,
        rental_duration INTEGER,
        is_active INTEGER DEFAULT 1,
        created_by TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(created_by) REFERENCES users(id)
    )''')
    
    # Orders
    c.execute('''CREATE TABLE IF NOT EXISTS orders (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        product_id TEXT NOT NULL,
        order_type TEXT NOT NULL,
        price REAL NOT NULL,
        status TEXT DEFAULT 'pending',
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(product_id) REFERENCES products(id)
    )''')
    
    # Rental history
    c.execute('''CREATE TABLE IF NOT EXISTS rentals (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        product_id TEXT NOT NULL,
        start_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        end_date TIMESTAMP NOT NULL,
        price REAL NOT NULL,
        is_active INTEGER DEFAULT 1,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(product_id) REFERENCES products(id)
    )''')
    
    # Transactions
    c.execute('''CREATE TABLE IF NOT EXISTS transactions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        type TEXT NOT NULL,
        amount REAL NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    
    conn.commit()
    conn.close()

init_db()

# ==================== AUTHENTICATION ====================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        
        conn = get_db_connection()
        user = conn.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        
        if not user or not user['is_admin']:
            return {'error': 'Unauthorized'}, 403
        
        return f(*args, **kwargs)
    return decorated_function

# ==================== ROUTES - AUTHENTICATION ====================
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if not all([username, email, password]):
        return {'error': 'Missing fields'}, 400
    
    conn = get_db_connection()
    try:
        user_id = str(uuid.uuid4())
        conn.execute('INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)',
                    (user_id, username, email, generate_password_hash(password)))
        conn.commit()
        return {'success': True, 'user_id': user_id}
    except sqlite3.IntegrityError:
        return {'error': 'Username or email already exists'}, 400
    finally:
        conn.close()

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    
    if not user or not check_password_hash(user['password'], password):
        return {'error': 'Invalid credentials'}, 401
    
    session['user_id'] = user['id']
    session['is_admin'] = bool(user['is_admin'])
    
    return {
        'success': True,
        'user_id': user['id'],
        'is_admin': bool(user['is_admin']),
        'username': user['username']
    }

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return {'success': True}

@app.route('/api/auth/me')
def get_current_user():
    if 'user_id' not in session:
        return None
    
    conn = get_db_connection()
    user = conn.execute('SELECT id, username, email, is_admin, balance FROM users WHERE id = ?',
                       (session['user_id'],)).fetchone()
    conn.close()
    
    return dict(user) if user else None

# ==================== ROUTES - PRODUCTS ====================
@app.route('/api/products')
def get_products():
    category = request.args.get('category')
    product_type = request.args.get('type')
    
    conn = get_db_connection()
    query = 'SELECT * FROM products WHERE is_active = 1'
    params = []
    
    if category:
        query += ' AND category = ?'
        params.append(category)
    
    if product_type:
        query += ' AND type = ?'
        params.append(product_type)
    
    products = conn.execute(query, params).fetchall()
    conn.close()
    
    return jsonify([dict(p) for p in products])

@app.route('/api/products/<product_id>')
def get_product(product_id):
    conn = get_db_connection()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    conn.close()
    
    if not product:
        return {'error': 'Not found'}, 404
    
    return jsonify(dict(product))

@app.route('/api/products', methods=['POST'])
@admin_required
def create_product():
    data = request.json
    product_id = str(uuid.uuid4())
    
    conn = get_db_connection()
    conn.execute('''INSERT INTO products 
                   (id, name, description, type, price, category, image_url, 
                    file_path, rental_price, rental_duration, created_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (product_id, data['name'], data.get('description'), data['type'],
                 data['price'], data['category'], data.get('image_url'),
                 data.get('file_path'), data.get('rental_price'),
                 data.get('rental_duration'), session['user_id']))
    conn.commit()
    conn.close()
    
    return {'success': True, 'product_id': product_id}

@app.route('/api/products/<product_id>', methods=['PUT'])
@admin_required
def update_product(product_id):
    data = request.json
    
    conn = get_db_connection()
    conn.execute('''UPDATE products SET name = ?, description = ?, price = ?,
                   category = ?, image_url = ? WHERE id = ?''',
                (data['name'], data.get('description'), data['price'],
                 data['category'], data.get('image_url'), product_id))
    conn.commit()
    conn.close()
    
    return {'success': True}

@app.route('/api/products/<product_id>', methods=['DELETE'])
@admin_required
def delete_product(product_id):
    conn = get_db_connection()
    conn.execute('UPDATE products SET is_active = 0 WHERE id = ?', (product_id,))
    conn.commit()
    conn.close()
    
    return {'success': True}

# ==================== ROUTES - ORDERS & RENTALS ====================
@app.route('/api/orders', methods=['POST'])
@login_required
def create_order():
    data = request.json
    product_id = data.get('product_id')
    order_type = data.get('type')  # 'buy' or 'rent'
    
    conn = get_db_connection()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    
    if not product:
        conn.close()
        return {'error': 'Product not found'}, 404
    
    user = conn.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if order_type == 'buy':
        price = product['price']
    elif order_type == 'rent':
        price = product['rental_price']
    else:
        conn.close()
        return {'error': 'Invalid order type'}, 400
    
    if user['balance'] < price:
        conn.close()
        return {'error': 'Insufficient balance'}, 400
    
    order_id = str(uuid.uuid4())
    expires_at = None
    
    if order_type == 'rent':
        expires_at = datetime.now() + timedelta(days=product['rental_duration'])
    
    conn.execute('''INSERT INTO orders 
                   (id, user_id, product_id, order_type, price, status, expires_at)
                   VALUES (?, ?, ?, ?, ?, 'completed', ?)''',
                (order_id, session['user_id'], product_id, order_type, price, expires_at))
    
    # Deduct balance
    conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?',
                (price, session['user_id']))
    
    # Record transaction
    trans_id = str(uuid.uuid4())
    conn.execute('''INSERT INTO transactions (id, user_id, type, amount, description)
                   VALUES (?, ?, 'purchase', ?, ?)''',
                (trans_id, session['user_id'], price, f'Purchased {product["name"]}'))
    
    conn.commit()
    conn.close()
    
    return {'success': True, 'order_id': order_id}

@app.route('/api/orders')
@login_required
def get_user_orders():
    conn = get_db_connection()
    orders = conn.execute('''SELECT o.*, p.name as product_name, p.type
                            FROM orders o
                            JOIN products p ON o.product_id = p.id
                            WHERE o.user_id = ?
                            ORDER BY o.created_at DESC''',
                         (session['user_id'],)).fetchall()
    conn.close()
    
    return jsonify([dict(o) for o in orders])

@app.route('/api/rentals')
@login_required
def get_user_rentals():
    conn = get_db_connection()
    rentals = conn.execute('''SELECT r.*, p.name as product_name, p.file_path
                             FROM rentals r
                             JOIN products p ON r.product_id = p.id
                             WHERE r.user_id = ? AND r.is_active = 1
                             AND r.end_date > datetime('now')''',
                          (session['user_id'],)).fetchall()
    conn.close()
    
    return jsonify([dict(r) for r in rentals])

# ==================== ROUTES - ADMIN DASHBOARD ====================
@app.route('/api/admin/stats')
@admin_required
def get_admin_stats():
    conn = get_db_connection()
    
    total_users = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
    total_products = conn.execute('SELECT COUNT(*) as count FROM products WHERE is_active = 1').fetchone()['count']
    total_orders = conn.execute('SELECT COUNT(*) as count FROM orders WHERE status = "completed"').fetchone()['count']
    total_revenue = conn.execute('SELECT SUM(amount) as total FROM transactions WHERE type = "purchase"').fetchone()['total'] or 0
    
    conn.close()
    
    return {
        'total_users': total_users,
        'total_products': total_products,
        'total_orders': total_orders,
        'total_revenue': total_revenue
    }

@app.route('/api/admin/users')
@admin_required
def get_all_users():
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, email, balance, created_at FROM users').fetchall()
    conn.close()
    
    return jsonify([dict(u) for u in users])

@app.route('/api/admin/all-orders')
@admin_required
def get_all_orders():
    conn = get_db_connection()
    orders = conn.execute('''SELECT o.*, u.username, p.name as product_name
                            FROM orders o
                            JOIN users u ON o.user_id = u.id
                            JOIN products p ON o.product_id = p.id
                            ORDER BY o.created_at DESC''').fetchall()
    conn.close()
    
    return jsonify([dict(o) for o in orders])

# ==================== ROUTES - WALLET ====================
@app.route('/api/wallet/topup', methods=['POST'])
@login_required
def topup_wallet():
    data = request.json
    amount = data.get('amount', 0)
    
    if amount <= 0:
        return {'error': 'Invalid amount'}, 400
    
    # In production, integrate with payment gateway here
    conn = get_db_connection()
    conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?',
                (amount, session['user_id']))
    
    trans_id = str(uuid.uuid4())
    conn.execute('''INSERT INTO transactions (id, user_id, type, amount, description)
                   VALUES (?, ?, 'topup', ?, 'Wallet topup')''',
                (trans_id, session['user_id'], amount))
    
    conn.commit()
    conn.close()
    
    return {'success': True}

@app.route('/api/wallet/balance')
@login_required
def get_balance():
    conn = get_db_connection()
    user = conn.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    return {'balance': user['balance'] if user else 0}

@app.route('/api/wallet/transactions')
@login_required
def get_transactions():
    conn = get_db_connection()
    transactions = conn.execute('''SELECT * FROM transactions
                                 WHERE user_id = ?
                                 ORDER BY created_at DESC
                                 LIMIT 50''',
                              (session['user_id'],)).fetchall()
    conn.close()
    
    return jsonify([dict(t) for t in transactions])

# ==================== ROUTES - PAGES ====================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/admin')
@login_required
def admin_page():
    conn = get_db_connection()
    user = conn.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    if not user or not user['is_admin']:
        return redirect('/')
    
    return render_template('admin.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/shop')
def shop():
    return render_template('shop.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
