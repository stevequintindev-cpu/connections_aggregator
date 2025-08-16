"""
LinkedIn Connection Aggregator Tool
A Flask-based application for aggregating and searching employee LinkedIn connections
"""

import os
import sqlite3
import pandas as pd
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import json
from fuzzywuzzy import fuzz, process
import re
from typing import List, Dict, Optional
import hashlib
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "your-secret-key-here")
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
CORS(app)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database setup
DB_PATH = 'connections.db'

def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Employees table
    c.execute('''
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            department TEXT,
            password_hash TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Connections table
    c.execute('''
        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            first_name TEXT,
            last_name TEXT,
            company TEXT,
            position TEXT,
            email TEXT,
            linkedin_url TEXT,
            connected_on DATE,
            connection_hash TEXT UNIQUE,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (employee_id) REFERENCES employees(id)
        )
    ''')
    
    # Company normalization table
    c.execute('''
        CREATE TABLE IF NOT EXISTS company_aliases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_name TEXT NOT NULL,
            normalized_name TEXT NOT NULL,
            confidence_score REAL
        )
    ''')
    
    # Search history for analytics
    c.execute('''
        CREATE TABLE IF NOT EXISTS search_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER,
            search_query TEXT,
            results_count INTEGER,
            searched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (employee_id) REFERENCES employees(id)
        )
    ''')
    
    # Create indexes for better performance
    c.execute('CREATE INDEX IF NOT EXISTS idx_company ON connections(company)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_employee ON connections(employee_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_hash ON connections(connection_hash)')
    
    conn.commit()
    conn.close()

class ConnectionProcessor:
    """Process and normalize LinkedIn CSV data"""
    
    @staticmethod
    def generate_connection_hash(row: pd.Series) -> str:
        """Generate unique hash for deduplication"""
        unique_str = f"{row.get('First Name', '')}{row.get('Last Name', '')}{row.get('Company', '')}{row.get('Email Address', '')}"
        return hashlib.md5(unique_str.lower().encode()).hexdigest()
    
    @staticmethod
    def normalize_company_name(company) -> str:
        """Normalize company names for better matching"""
        # Handle None, NaN, or empty values
        if pd.isna(company) or not company or str(company).strip() == '':
            return ""
        
        # Convert to string and clean
        company_str = str(company).strip()
        if not company_str:
            return ""
        
        # Remove common suffixes
        suffixes = [' LLC', ' Inc.', ' Inc', ' Corporation', ' Corp.', ' Corp', 
                   ' Ltd.', ' Ltd', ' Limited', ' GmbH', ' AG', ' SA', ' PLC']
        normalized = company_str
        for suffix in suffixes:
            normalized = re.sub(f'{suffix}$', '', normalized, flags=re.IGNORECASE)
        
        # Remove extra spaces and convert to title case
        normalized = ' '.join(normalized.split()).title()
        return normalized
    
    @staticmethod
    def process_csv(file_path: str, employee_id: int) -> Dict:
        """Process uploaded CSV file"""
        try:
            # Read CSV with multiple encoding attempts and error handling
            encodings = ['utf-8', 'latin-1', 'iso-8859-1']
            df = None
            
            for encoding in encodings:
                try:
                    # First, find the actual header row in LinkedIn export format
                    with open(file_path, 'r', encoding=encoding) as f:
                        lines = f.readlines()
                    
                    # Find the line that contains "First Name,Last Name" which is the actual header
                    header_line_index = 0
                    for i, line in enumerate(lines):
                        if 'First Name' in line and 'Last Name' in line:
                            header_line_index = i
                            break
                    
                    # Read CSV starting from the actual header line
                    df = pd.read_csv(file_path, encoding=encoding, 
                                   skiprows=header_line_index,
                                   skipinitialspace=True,
                                   on_bad_lines='skip',
                                   quoting=1)  # QUOTE_ALL
                    break
                except (UnicodeDecodeError, pd.errors.ParserError):
                    try:
                        # Try with different delimiter and quoting
                        df = pd.read_csv(file_path, encoding=encoding,
                                       sep=',',
                                       skipinitialspace=True,
                                       on_bad_lines='skip',
                                       quotechar='"',
                                       doublequote=True,
                                       escapechar=None)
                        break
                    except (UnicodeDecodeError, pd.errors.ParserError):
                        try:
                            # Try with semicolon delimiter (common in European exports)
                            df = pd.read_csv(file_path, encoding=encoding,
                                           sep=';',
                                           skipinitialspace=True,
                                           on_bad_lines='skip')
                            break
                        except (UnicodeDecodeError, pd.errors.ParserError):
                            continue
            
            if df is None:
                # If all parsing attempts failed, provide diagnostic information
                try:
                    # Read first few lines as text to diagnose the issue
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()[:10]  # First 10 lines for diagnosis
                    
                    diagnostic_info = []
                    for i, line in enumerate(lines, 1):
                        line = line.strip()
                        if line:
                            field_count = len(line.split(','))
                            diagnostic_info.append(f"Line {i}: {field_count} fields - {line[:100]}...")
                    
                    return {'error': f'Could not parse CSV file. Diagnostic info:\n' + '\n'.join(diagnostic_info[:5]) + 
                           '\n\nCommon issues:\n- Mixed delimiters (semicolons vs commas)\n- Unescaped quotes in data\n- Different number of fields per row\n- Special characters or encoding issues'}
                except:
                    return {'error': 'Could not read CSV file. Please ensure it is a properly formatted CSV with comma separators.'}
            
            # Clean column names (remove extra spaces, standardize case)
            df.columns = df.columns.str.strip()
            
            # Map common column variations to standard names
            column_mapping = {
                'first name': 'First Name',
                'firstname': 'First Name',
                'fname': 'First Name',
                'last name': 'Last Name', 
                'lastname': 'Last Name',
                'lname': 'Last Name',
                'company': 'Company',
                'organization': 'Company',
                'employer': 'Company',
                'position': 'Position',
                'title': 'Position',
                'job title': 'Position',
                'connected on': 'Connected On',
                'connection date': 'Connected On',
                'date connected': 'Connected On'
            }
            
            # Rename columns to standard format
            df.columns = [column_mapping.get(col.lower(), col) for col in df.columns]
            
            # Expected columns (LinkedIn format)
            expected_cols = ['First Name', 'Last Name', 'Company', 'Position', 'Connected On']
            
            # Check if essential columns exist (first 3 are required)
            missing_cols = [col for col in expected_cols[:3] if col not in df.columns]
            if missing_cols:
                available_cols = list(df.columns)
                return {'error': f'Missing required columns: {missing_cols}. Available columns: {available_cols}. Please ensure your CSV has columns for First Name, Last Name, and Company.'}
            
            # Process connections
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            
            new_connections = 0
            duplicate_connections = 0
            
            for _, row in df.iterrows():
                # Generate hash for deduplication
                connection_hash = ConnectionProcessor.generate_connection_hash(row)
                
                # Check if connection already exists
                c.execute('SELECT id FROM connections WHERE connection_hash = ?', (connection_hash,))
                if c.fetchone():
                    duplicate_connections += 1
                    continue
                
                # Parse connected date
                connected_date = None
                connected_on_value = row.get('Connected On')
                if connected_on_value is not None and not (isinstance(connected_on_value, float) and pd.isna(connected_on_value)):
                    try:
                        dt_obj = pd.to_datetime(str(connected_on_value))
                        connected_date = dt_obj.date() if hasattr(dt_obj, 'date') else dt_obj
                    except:
                        pass
                
                # Clean and prepare data for insertion
                first_name = str(row.get('First Name', '')).strip() if pd.notna(row.get('First Name')) and row.get('First Name') is not None else ''
                last_name = str(row.get('Last Name', '')).strip() if pd.notna(row.get('Last Name')) and row.get('Last Name') is not None else ''
                company = ConnectionProcessor.normalize_company_name(row.get('Company'))
                position = str(row.get('Position', '')).strip() if pd.notna(row.get('Position')) and row.get('Position') is not None else ''
                email = str(row.get('Email Address', '')).strip() if pd.notna(row.get('Email Address')) and row.get('Email Address') is not None else ''
                
                # Insert new connection
                c.execute('''
                    INSERT INTO connections 
                    (employee_id, first_name, last_name, company, position, email, 
                     connected_on, connection_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    employee_id,
                    first_name,
                    last_name,
                    company,
                    position,
                    email,
                    connected_date,
                    connection_hash
                ))
                new_connections += 1
            
            conn.commit()
            conn.close()
            
            return {
                'success': True,
                'new_connections': new_connections,
                'duplicates': duplicate_connections,
                'total_processed': len(df)
            }
            
        except Exception as e:
            app.logger.error(f"CSV processing error: {str(e)}", exc_info=True)
            return {'error': str(e)}

class AgenticSearch:
    """AI-powered natural language search interface"""
    
    @staticmethod
    def parse_query(query: str) -> Dict:
        """Parse natural language query to extract intent and entities"""
        query_lower = query.lower()
        
        # Extract company names (simple heuristic)
        company_patterns = [
            r'at\s+([A-Z][A-Za-z\s&]+)',
            r'from\s+([A-Z][A-Za-z\s&]+)',
            r'(?:who knows|connected to)\s+(?:someone|anyone|people)\s+(?:at|from)\s+([A-Z][A-Za-z\s&]+)',
            r'connections?\s+(?:at|to|with)\s+([A-Z][A-Za-z\s&]+)'
        ]
        
        companies = []
        for pattern in company_patterns:
            matches = re.findall(pattern, query, re.IGNORECASE)
            companies.extend(matches)
        
        # Clean up company names
        companies = [c.strip() for c in companies]
        
        # Extract person names from various patterns
        name_patterns = [
            r'(?:find|search|show|who is)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)',
            r'([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s+(?:contact|connection)',
            r'(?:contact|connection)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)',
            r'^([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)$'  # Just a name by itself
        ]
        
        names = []
        for pattern in name_patterns:
            matches = re.findall(pattern, query, re.IGNORECASE)
            names.extend(matches)
        
        # Clean up names and remove common words
        common_words = {'find', 'search', 'show', 'who', 'is', 'contact', 'connection', 'at', 'from', 'in', 'the', 'a', 'an'}
        names = [n.strip() for n in names if n.strip().lower() not in common_words and len(n.strip()) > 1]
        
        # If no specific patterns matched, check if the query might be a simple name search
        if not companies and not names:
            # Simple check: if query contains 1-2 capitalized words, treat as name search
            words = query.strip().split()
            if 1 <= len(words) <= 2 and all(word[0].isupper() for word in words if word.isalpha()):
                names = [query.strip()]
        
        # Determine query type
        query_type = 'search'
        if 'how many' in query_lower:
            query_type = 'count'
        elif 'top' in query_lower or 'most' in query_lower:
            query_type = 'analytics'
        
        return {
            'type': query_type,
            'companies': companies,
            'names': names,
            'original_query': query
        }
    
    @staticmethod
    def execute_search(parsed_query: Dict, employee_id: Optional[int] = None) -> Dict:
        """Execute search based on parsed query"""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        results = []
        
        if parsed_query['type'] == 'search':
            # Search by company names
            if parsed_query['companies']:
                for company in parsed_query['companies']:
                    # Use fuzzy matching for company names
                    c.execute('SELECT DISTINCT company FROM connections WHERE company IS NOT NULL AND company != ""')
                    all_companies = [row['company'] for row in c.fetchall()]
                    
                    if all_companies:
                        # Find best matches
                        matches = process.extract(company, all_companies, scorer=fuzz.token_sort_ratio, limit=3)
                        
                        for match_result in matches:
                            matched_company, score = match_result[0], match_result[1]
                            if score > 70:  # Threshold for match confidence
                                c.execute('''
                                    SELECT c.*, e.name as employee_name, e.email as employee_email
                                    FROM connections c
                                    JOIN employees e ON c.employee_id = e.id
                                    WHERE c.company = ?
                                    ORDER BY c.first_name, c.last_name
                                ''', (matched_company,))
                                
                                for row in c.fetchall():
                                    results.append({
                                        'connection_name': f"{row['first_name']} {row['last_name']}",
                                        'company': row['company'],
                                        'position': row['position'],
                                        'employee_name': row['employee_name'],
                                        'employee_email': row['employee_email'],
                                        'match_confidence': score
                                    })
            
            # Search by contact names
            if parsed_query['names']:
                for name in parsed_query['names']:
                    # Get all connection names for fuzzy matching
                    c.execute('''
                        SELECT c.*, e.name as employee_name, e.email as employee_email,
                               (c.first_name || ' ' || c.last_name) as full_name
                        FROM connections c
                        JOIN employees e ON c.employee_id = e.id
                        WHERE c.first_name IS NOT NULL AND c.last_name IS NOT NULL
                    ''')
                    
                    all_connections = c.fetchall()
                    if all_connections:
                        # Prepare data for fuzzy matching
                        connection_names = []
                        connection_data = {}
                        
                        for row in all_connections:
                            full_name = f"{row['first_name']} {row['last_name']}".strip()
                            first_name = row['first_name'].strip() if row['first_name'] else ''
                            last_name = row['last_name'].strip() if row['last_name'] else ''
                            
                            # Add full name, first name, and last name for matching
                            for match_name in [full_name, first_name, last_name]:
                                if match_name and len(match_name) > 1:
                                    connection_names.append(match_name)
                                    connection_data[match_name] = row
                        
                        # Find best matches using fuzzy matching
                        if connection_names:
                            matches = process.extract(name, connection_names, scorer=fuzz.token_sort_ratio, limit=10)
                            
                            for match_result in matches:
                                matched_name, score = match_result[0], match_result[1]
                                if score > 60:  # Lower threshold for name matching
                                    row = connection_data[matched_name]
                                    result = {
                                        'connection_name': f"{row['first_name']} {row['last_name']}",
                                        'company': row['company'],
                                        'position': row['position'],
                                        'employee_name': row['employee_name'],
                                        'employee_email': row['employee_email'],
                                        'match_confidence': score
                                    }
                                    # Avoid duplicates
                                    if result not in results:
                                        results.append(result)
        
        # Log search
        if employee_id:
            c.execute('''
                INSERT INTO search_history (employee_id, search_query, results_count)
                VALUES (?, ?, ?)
            ''', (employee_id, parsed_query['original_query'], len(results)))
            conn.commit()
        
        conn.close()
        
        return {
            'query': parsed_query,
            'results': results,
            'count': len(results)
        }

# Helper functions
def get_current_user():
    """Get current logged-in user"""
    if 'user_id' not in session:
        return None
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM employees WHERE id = ?', (session['user_id'],))
    user = c.fetchone()
    conn.close()
    return user

# Routes
@app.route('/')
def index():
    """Serve the main HTML interface"""
    user = get_current_user()
    if user:
        # Redirect logged-in users to dashboard
        return redirect(url_for('dashboard'))
    return render_template('index.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login"""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Email and password are required', 'error')
            return render_template('index.html')
        
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT * FROM employees WHERE email = ?', (email,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')
    
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration"""
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')
        department = request.form.get('department', '')
        
        if not all([email, name, password]):
            flash('Email, name, and password are required', 'error')
            return render_template('index.html')
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # Check if user exists
        c.execute('SELECT id FROM employees WHERE email = ?', (email,))
        if c.fetchone():
            conn.close()
            flash('User already exists', 'error')
            return render_template('index.html')
        
        # Create user - all new accounts are admin accounts
        password_hash = generate_password_hash(password or '')
        admin_department = department if department else 'Admin'
        c.execute('''
            INSERT INTO employees (email, name, department, password_hash)
            VALUES (?, ?, ?, ?)
        ''', (email, name, admin_department, password_hash))
        
        conn.commit()
        employee_id = c.lastrowid
        conn.close()
        
        session['user_id'] = employee_id
        session['user_name'] = name
        flash('Registration successful!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('index.html')

@app.route('/logout')
def logout():
    """Handle user logout"""
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/change_password', methods=['POST'])
def change_password():
    """Handle password change"""
    user = get_current_user()
    if not user:
        flash('Please log in to change password', 'error')
        return redirect(url_for('index'))
    
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not all([current_password, new_password, confirm_password]):
        flash('All password fields are required', 'error')
        return redirect(url_for('dashboard'))
    
    if new_password != confirm_password:
        flash('New passwords do not match', 'error')
        return redirect(url_for('dashboard'))
    
    if len(new_password) < 6:
        flash('New password must be at least 6 characters long', 'error')
        return redirect(url_for('dashboard'))
    
    # Verify current password
    if not user['password_hash'] or not check_password_hash(user['password_hash'], current_password):
        flash('Current password is incorrect', 'error')
        return redirect(url_for('dashboard'))
    
    # Update password
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    new_password_hash = generate_password_hash(new_password)
    c.execute('UPDATE employees SET password_hash = ? WHERE id = ?', 
              (new_password_hash, user['id']))
    conn.commit()
    conn.close()
    
    flash('Password changed successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    """Handle forgot password requests"""
    email = request.form.get('email')
    
    if not email:
        flash('Email address is required', 'error')
        return redirect(url_for('index'))
    
    # Check if user exists
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM employees WHERE email = ?', (email,))
    user = c.fetchone()
    
    if not user:
        # Don't reveal if email exists or not for security
        flash('If an account with that email exists, a reset link has been sent.', 'info')
        return redirect(url_for('index'))
    
    # Generate a temporary password
    import secrets
    import string
    temp_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
    
    # Update user with temporary password
    temp_password_hash = generate_password_hash(temp_password)
    c.execute('UPDATE employees SET password_hash = ? WHERE id = ?', 
              (temp_password_hash, user['id']))
    conn.commit()
    conn.close()
    
    # Try to send email (will work if SENDGRID_API_KEY is provided)
    try:
        from sendgrid import SendGridAPIClient
        from sendgrid.helpers.mail import Mail
        
        sendgrid_key = os.environ.get('SENDGRID_API_KEY')
        if sendgrid_key:
            message = Mail(
                from_email='noreply@connection-aggregator.com',
                to_emails=email,
                subject='Password Reset - LinkedIn Connection Aggregator',
                html_content=f'''
                <h2>Password Reset</h2>
                <p>Hello {user['name']},</p>
                <p>Your password has been reset. You can now log in with this temporary password:</p>
                <p><strong>{temp_password}</strong></p>
                <p>Please log in and change your password immediately for security.</p>
                <p>If you didn't request this reset, please contact your administrator.</p>
                '''
            )
            
            sg = SendGridAPIClient(sendgrid_key)
            sg.send(message)
            flash('A temporary password has been sent to your email address.', 'success')
        else:
            # Fallback: show the password directly (for development/demo)
            flash(f'Email service not configured. Your temporary password is: {temp_password}', 'warning')
            
    except Exception as e:
        app.logger.error(f"Email sending failed: {str(e)}")
        # Fallback: show the password directly
        flash(f'Email service unavailable. Your temporary password is: {temp_password}', 'warning')
    
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    """Main dashboard page"""
    user = get_current_user()
    if not user:
        flash('Please log in to access the dashboard', 'error')
        return redirect(url_for('index'))
    
    # Get user statistics
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Total connections
    c.execute('SELECT COUNT(*) as count FROM connections WHERE employee_id = ?', (user['id'],))
    total_connections = c.fetchone()['count']
    
    # Top companies
    c.execute('''
        SELECT company, COUNT(*) as count 
        FROM connections 
        WHERE employee_id = ? AND company IS NOT NULL AND company != ""
        GROUP BY company 
        ORDER BY count DESC 
        LIMIT 5
    ''', (user['id'],))
    top_companies = c.fetchall()
    
    # Recent searches
    c.execute('''
        SELECT search_query, results_count, searched_at 
        FROM search_history 
        WHERE employee_id = ? 
        ORDER BY searched_at DESC 
        LIMIT 5
    ''', (user['id'],))
    recent_searches = c.fetchall()
    
    conn.close()
    
    return render_template('index.html', user=user, dashboard=True, 
                         total_connections=total_connections,
                         top_companies=top_companies,
                         recent_searches=recent_searches)

@app.route('/upload', methods=['POST'])
def upload_csv():
    """Upload and process multiple LinkedIn connections CSV files"""
    user = get_current_user()
    if not user:
        flash('Please log in to upload files', 'error')
        return redirect(url_for('index'))
    
    files = request.files.getlist('files')
    if not files or all(f.filename == '' for f in files):
        flash('No files selected', 'error')
        return redirect(url_for('dashboard'))
    
    auto_detect_names = request.form.get('auto_detect_names') == 'on'
    
    total_new = 0
    total_duplicates = 0
    processed_files = 0
    failed_files = []
    
    for file in files:
        if not file or not file.filename or file.filename == '' or not file.filename.lower().endswith('.csv'):
            continue
            
        filename = secure_filename(file.filename or '')
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Extract employee name from filename if auto-detect is enabled
        employee_name = None
        employee_email = None
        
        if auto_detect_names:
            # Try to extract name from filename
            name_part = filename.replace('.csv', '').replace('_connections', '').replace('_contacts', '')
            name_part = name_part.replace('_', ' ').replace('-', ' ')
            # Clean up common patterns
            name_part = ' '.join([word.capitalize() for word in name_part.split() if word.lower() not in ['linkedin', 'export', 'data']])
            if name_part.strip():
                employee_name = name_part.strip()
                # Generate a placeholder email
                employee_email = f"{employee_name.lower().replace(' ', '.')}@company.com"
        
        # If we couldn't detect a name, use the filename
        if not employee_name:
            employee_name = filename.replace('.csv', '').replace('_', ' ').title()
            employee_email = f"{employee_name.lower().replace(' ', '.')}@company.com"
        
        # Create or get employee record
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # Check if employee already exists
        c.execute('SELECT id FROM employees WHERE email = ?', (employee_email,))
        employee_record = c.fetchone()
        
        if not employee_record:
            # Create new employee record (no password needed for CSV-imported employees)
            c.execute('''
                INSERT INTO employees (name, email, department, password_hash) 
                VALUES (?, ?, ?, NULL)
            ''', (employee_name, employee_email, 'Imported'))
            employee_id = c.lastrowid
        else:
            employee_id = employee_record[0]
        
        conn.commit()
        conn.close()
        
        # Process the CSV for this employee
        app.logger.info(f"Processing CSV file: {filename} for employee {employee_name} (ID: {employee_id})")
        result = ConnectionProcessor.process_csv(filepath, employee_id)
        app.logger.info(f"CSV processing result: {result}")
        
        # Clean up uploaded file
        try:
            os.remove(filepath)
        except:
            pass
        
        if result.get('success'):
            total_new += result.get('new_connections', 0)
            total_duplicates += result.get('duplicates', 0)
            processed_files += 1
        else:
            failed_files.append(f"{filename}: {result.get('error', 'Unknown error')}")
    
    # Show summary message
    if processed_files > 0:
        message = f'Successfully processed {processed_files} files! Added {total_new} new connections. {total_duplicates} duplicates were skipped.'
        if failed_files:
            message += f' Failed files: {"; ".join(failed_files)}'
        flash(message, 'success' if not failed_files else 'warning')
    else:
        flash('No valid CSV files were processed', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/search', methods=['POST'])
def search():
    """Handle search requests"""
    user = get_current_user()
    if not user:
        flash('Please log in to search', 'error')
        return redirect(url_for('index'))
    
    query = request.form.get('query', '').strip()
    if not query:
        flash('Please enter a search query', 'error')
        return redirect(url_for('dashboard'))
    
    # Parse and execute search
    parsed_query = AgenticSearch.parse_query(query)
    search_results = AgenticSearch.execute_search(parsed_query, user['id'])
    
    return render_template('index.html', user=user, dashboard=True,
                         search_query=query, search_results=search_results)

@app.route('/download_results', methods=['POST'])
def download_results():
    """Download search results as CSV"""
    user = get_current_user()
    if not user:
        flash('Please log in to download results', 'error')
        return redirect(url_for('index'))
    
    query = request.form.get('search_query', '').strip()
    if not query:
        flash('No search query provided', 'error')
        return redirect(url_for('dashboard'))
    
    # Re-execute search to get results
    parsed_query = AgenticSearch.parse_query(query)
    search_results = AgenticSearch.execute_search(parsed_query, user['id'])
    
    if not search_results.get('results'):
        flash('No results to download', 'error')
        return redirect(url_for('dashboard'))
    
    # Create CSV content
    import io
    output = io.StringIO()
    output.write('Connection Name,Company,Position,Employee Contact,Employee Email,Match Confidence\n')
    
    for result in search_results['results']:
        # Escape commas and quotes in CSV data
        connection_name = str(result.get('connection_name', '')).replace('"', '""')
        company = str(result.get('company', '')).replace('"', '""')
        position = str(result.get('position', '')).replace('"', '""')
        employee_name = str(result.get('employee_name', '')).replace('"', '""')
        employee_email = str(result.get('employee_email', '')).replace('"', '""')
        confidence = str(result.get('match_confidence', ''))
        
        output.write(f'"{connection_name}","{company}","{position}","{employee_name}","{employee_email}",{confidence}\n')
    
    csv_content = output.getvalue()
    output.close()
    
    # Create response with CSV file
    from flask import make_response
    response = make_response(csv_content)
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=search_results_{user["name"].replace(" ", "_")}.csv'
    
    return response

@app.route('/api/analytics')
def analytics():
    """Get analytics data for dashboard"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Get company distribution
    c.execute('''
        SELECT company, COUNT(*) as count 
        FROM connections 
        WHERE employee_id = ? AND company IS NOT NULL AND company != ""
        GROUP BY company 
        ORDER BY count DESC 
        LIMIT 10
    ''', (user['id'],))
    companies = [{'name': row['company'], 'count': row['count']} for row in c.fetchall()]
    
    # Get monthly connection trends
    c.execute('''
        SELECT strftime('%Y-%m', connected_on) as month, COUNT(*) as count
        FROM connections 
        WHERE employee_id = ? AND connected_on IS NOT NULL
        GROUP BY month 
        ORDER BY month DESC 
        LIMIT 12
    ''', (user['id'],))
    trends = [{'month': row['month'], 'count': row['count']} for row in c.fetchall()]
    
    conn.close()
    
    return jsonify({
        'companies': companies,
        'trends': trends
    })

# Initialize database on startup
init_db()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
