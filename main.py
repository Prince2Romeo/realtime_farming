from __future__ import annotations

import os
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, request, render_template_string, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from pymongo import MongoClient, DESCENDING
from pymongo.errors import PyMongoError
from bson import json_util, ObjectId
from dotenv import load_dotenv
import bcrypt

# Load environment variables from .env file
load_dotenv()

# ---- Configuration ----
MONGODB_URI = os.getenv("MONGODB_URI")
DB_NAME = os.getenv("DB_NAME", "farm")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "readings")
HOST = os.getenv("FLASK_HOST", "0.0.0.0")
PORT = int(os.getenv("FLASK_PORT", "5000"))
DEBUG = os.getenv("FLASK_DEBUG", "1") == "1"


def get_db():
    if not MONGODB_URI:
        raise ValueError("MongoDB connection string is not set. Please set MONGODB_URI in .env file")
    client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
    return client[DB_NAME]


def get_collection():
    return get_db()[COLLECTION_NAME]


# ---- Flask App ----
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "your-secret-key-change-this-in-production")

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access the dashboard.'
login_manager.login_message_category = 'info'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.email = user_data['email']
        self.created_at = user_data.get('created_at')

@login_manager.user_loader
def load_user(user_id):
    try:
        user_data = get_db()['users'].find_one({'_id': ObjectId(user_id)})
        if user_data:
            return User(user_data)
    except:
        pass
    return None

def get_users_collection():
    return get_db()['users']


@app.route("/api/health")
def health():
    try:
        # Ping the server
        get_db().command("ping")
        return jsonify({"status": "ok", "mongo": "connected"})
    except Exception as e:
        return jsonify({"status": "degraded", "mongo": f"error: {str(e)}"}), 503


@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        
        if not username or not email or not password:
            return jsonify({'error': 'All fields are required'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        try:
            users_col = get_users_collection()
            
            # Check if user already exists
            if users_col.find_one({'$or': [{'username': username}, {'email': email}]}):
                return jsonify({'error': 'Username or email already exists'}), 400
            
            # Hash password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            # Create user
            user_data = {
                'username': username,
                'email': email,
                'password': hashed_password,
                'created_at': datetime.now(timezone.utc)
            }
            
            result = users_col.insert_one(user_data)
            user_data['_id'] = result.inserted_id
            
            # Log in the user
            user = User(user_data)
            login_user(user)
            
            return jsonify({'success': True, 'redirect': url_for('dashboard')})
            
        except PyMongoError as e:
            return jsonify({'error': 'Database error occurred'}), 500
    
    return render_template_string(AUTH_HTML, mode='register')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        
        try:
            users_col = get_users_collection()
            user_data = users_col.find_one({'$or': [{'username': username}, {'email': username}]})
            
            if user_data and bcrypt.checkpw(password.encode('utf-8'), user_data['password']):
                user = User(user_data)
                login_user(user, remember=True)
                return jsonify({'success': True, 'redirect': url_for('dashboard')})
            else:
                return jsonify({'error': 'Invalid username or password'}), 401
                
        except PyMongoError as e:
            return jsonify({'error': 'Database error occurred'}), 500
    
    return render_template_string(AUTH_HTML, mode='login')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/api/sensors")
@login_required
def api_sensors():
    """Return distinct sensor names and optional locations for UI population."""
    try:
        col = get_collection()
        sensors = sorted(col.distinct("sensor"))
        locations = sorted([l for l in col.distinct("location") if l])
        return jsonify({"sensors": sensors, "locations": locations})
    except PyMongoError as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/summary")
@login_required
def api_summary():
    """
    Returns a summary of the latest reading per sensor type and basic stats.
    Expected schema examples in the collection `readings`:
    {
        "sensor": "soil_moisture",   # string
        "value": 34.2,               # number
        "unit": "%",                # string
        "timestamp": ISODate(...)    # datetime
        "location": "field-1"       # optional
    }
    """
    try:
        col = get_collection()
        # Get latest document per sensor (and optionally per location)
        pipeline = [
            {"$sort": {"sensor": 1, "location": 1, "timestamp": -1}},
            {"$group": {
                "_id": {"sensor": "$sensor", "location": {"$ifNull": ["$location", "__none__"]}},
                "latest": {"$first": "$$ROOT"}
            }},
            {"$replaceRoot": {"newRoot": "$latest"}},
            {"$project": {"_id": 0}}
        ]
        latest = list(col.aggregate(pipeline))

        # Basic stats for last 24h per sensor
        since = datetime.now(timezone.utc) - timedelta(hours=24)
        stats_pipeline = [
            {"$match": {"timestamp": {"$gte": since}}},
            {"$group": {
                "_id": {"sensor": "$sensor"},
                "count": {"$sum": 1},
                "min": {"$min": "$value"},
                "max": {"$max": "$value"},
                "avg": {"$avg": "$value"}
            }},
            {"$project": {"_id": 0, "sensor": "$_id.sensor", "count": 1, "min": 1, "max": 1, "avg": 1}}
        ]
        stats = list(col.aggregate(stats_pipeline))

        return jsonify({
            "latest": json.loads(json_util.dumps(latest)),
            "stats_24h": json.loads(json_util.dumps(stats)),
        })
    except PyMongoError as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/timeseries")
@login_required
def api_timeseries():
    """
    Query params:
      - sensor: required, e.g. soil_moisture
      - hours: optional int (default 24)
      - location: optional filter
      - limit: optional max docs (default 1000)
    Returns: descending timestamp series of {timestamp, value, unit}
    """
    sensor = request.args.get("sensor")
    if not sensor:
        return jsonify({"error": "Missing required parameter: sensor"}), 400

    hours = int(request.args.get("hours", 24))
    limit = int(request.args.get("limit", 1000))
    location = request.args.get("location")

    try:
        col = get_collection()
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        query: Dict[str, Any] = {"sensor": sensor, "timestamp": {"$gte": since}}
        if location:
            query["location"] = location

        cursor = col.find(query, {"_id": 0, "sensor": 1, "value": 1, "unit": 1, "timestamp": 1, "location": 1}) \
                     .sort("timestamp", DESCENDING) \
                     .limit(limit)
        docs = list(cursor)
        # Return in ascending order for charting
        docs_sorted = sorted(docs, key=lambda d: d.get("timestamp"))
        return jsonify(json.loads(json_util.dumps(docs_sorted)))
    except PyMongoError as e:
        return jsonify({"error": str(e)}), 500


# ---- Authentication UI ----
AUTH_HTML = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{% if mode == 'register' %}Sign Up{% else %}Login{% endif %} - Farm Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/animate.css@4.1.1/animate.min.css" rel="stylesheet">
    <style>
      :root {
        --brand: #198754;
        --glass-bg: rgba(255, 255, 255, 0.15);
        --glass-border: rgba(255, 255, 255, 0.2);
        --glass-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
      }
      
      body {
        background: linear-gradient(135deg, rgba(25, 135, 84, 0.1) 0%, rgba(40, 167, 69, 0.05) 100%),
                    url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 800"><defs><pattern id="farm" patternUnits="userSpaceOnUse" width="120" height="120"><rect width="120" height="120" fill="%23f8f9fa"/><circle cx="20" cy="20" r="2" fill="%23198754" opacity="0.1"/><circle cx="60" cy="40" r="1.5" fill="%2328a745" opacity="0.08"/><circle cx="100" cy="80" r="2.5" fill="%23198754" opacity="0.06"/><path d="M10 100 Q30 90 50 100 T90 100" stroke="%23198754" stroke-width="0.5" fill="none" opacity="0.1"/></pattern></defs><rect width="100%25" height="100%25" fill="url(%23farm)"/></svg>') center/cover;
        background-attachment: fixed;
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
      }
      
      .auth-card {
        background: var(--glass-bg);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border: 1px solid var(--glass-border);
        box-shadow: var(--glass-shadow);
        border-radius: 20px;
        width: 100%;
        max-width: 400px;
        transition: all 0.3s ease;
      }
      
      .auth-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 15px 45px rgba(31, 38, 135, 0.4);
      }
      
      .form-control {
        background: rgba(255, 255, 255, 0.1);
        backdrop-filter: blur(8px);
        border: 1px solid rgba(255, 255, 255, 0.2);
        border-radius: 12px;
        transition: all 0.3s ease;
      }
      
      .form-control:focus {
        background: rgba(255, 255, 255, 0.2);
        border-color: var(--brand);
        box-shadow: 0 0 0 0.2rem rgba(25, 135, 84, 0.25);
      }
      
      .btn-success {
        background: linear-gradient(135deg, #198754, #28a745);
        border: none;
        border-radius: 12px;
        box-shadow: 0 4px 15px rgba(25, 135, 84, 0.3);
        transition: all 0.3s ease;
      }
      
      .btn-success:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(25, 135, 84, 0.4);
      }
      
      .floating {
        animation: floating 3s ease-in-out infinite;
      }
      
      @keyframes floating {
        0%, 100% { transform: translateY(0px); }
        50% { transform: translateY(-10px); }
      }
      
      [data-bs-theme="dark"] {
        --glass-bg: rgba(18, 26, 31, 0.3);
        --glass-border: rgba(255, 255, 255, 0.1);
        --glass-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.5);
      }
      
      [data-bs-theme="dark"] body {
        background: linear-gradient(135deg, rgba(15, 20, 23, 0.9) 0%, rgba(18, 26, 31, 0.8) 100%),
                    url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 800"><defs><pattern id="farm-dark" patternUnits="userSpaceOnUse" width="120" height="120"><rect width="120" height="120" fill="%23121a1f"/><circle cx="20" cy="20" r="2" fill="%23198754" opacity="0.2"/><circle cx="60" cy="40" r="1.5" fill="%2328a745" opacity="0.15"/><circle cx="100" cy="80" r="2.5" fill="%23198754" opacity="0.1"/><path d="M10 100 Q30 90 50 100 T90 100" stroke="%23198754" stroke-width="0.5" fill="none" opacity="0.2"/></pattern></defs><rect width="100%25" height="100%25" fill="url(%23farm-dark)"/></svg>') center/cover;
      }
      
      [data-bs-theme="dark"] .form-control {
        background: rgba(255, 255, 255, 0.05);
        color: #dce3e8;
      }
      
      /* Mobile responsiveness for auth page */
      @media (max-width: 768px) {
        .auth-card {
          margin: 1rem;
          padding: 1.5rem !important;
        }
        
        .auth-card h2 {
          font-size: 1.5rem;
        }
        
        .auth-card .fs-1 {
          font-size: 2.5rem !important;
        }
        
        .form-control {
          padding: 0.75rem;
          font-size: 1rem;
        }
        
        .btn {
          padding: 0.75rem 1rem;
          font-size: 1rem;
        }
      }
      
      @media (max-width: 480px) {
        body {
          padding: 0.5rem;
        }
        
        .auth-card {
          margin: 0.5rem;
          padding: 1rem !important;
        }
        
        .auth-card h2 {
          font-size: 1.25rem;
        }
        
        .auth-card p {
          font-size: 0.9rem;
        }
        
        .auth-card .fs-1 {
          font-size: 2rem !important;
        }
        
        .form-label {
          font-size: 0.9rem;
        }
        
        .form-control {
          padding: 0.6rem;
          font-size: 0.9rem;
        }
        
        .btn {
          padding: 0.6rem 1rem;
          font-size: 0.9rem;
        }
        
        .alert {
          padding: 0.5rem 0.75rem;
          font-size: 0.85rem;
        }
      }
    </style>
  </head>
  <body>
    <div class="container-fluid d-flex align-items-center justify-content-center min-vh-100 p-3">
    <div class="auth-card animate__animated animate__fadeInUp p-4 w-100">
      <div class="text-center mb-4">
        <i class="bi bi-flower1 fs-1 text-success floating mb-3"></i>
        <h2 class="fw-bold">{% if mode == 'register' %}Create Account{% else %}Welcome Back{% endif %}</h2>
        <p class="text-muted">{% if mode == 'register' %}Join the Farm Dashboard{% else %}Sign in to your account{% endif %}</p>
      </div>
      
      <div id="alert-container"></div>
      
      <form id="authForm">
        {% if mode == 'register' %}
        <div class="mb-3">
          <label for="username" class="form-label">Username</label>
          <input type="text" class="form-control" id="username" required>
        </div>
        <div class="mb-3">
          <label for="email" class="form-label">Email</label>
          <input type="email" class="form-control" id="email" required>
        </div>
        {% else %}
        <div class="mb-3">
          <label for="username" class="form-label">Username or Email</label>
          <input type="text" class="form-control" id="username" required>
        </div>
        {% endif %}
        <div class="mb-3">
          <label for="password" class="form-label">Password</label>
          <input type="password" class="form-control" id="password" required>
        </div>
        <button type="submit" class="btn btn-success w-100 mb-3" id="submitBtn">
          <span class="spinner-border spinner-border-sm me-2 d-none" id="spinner"></span>
          {% if mode == 'register' %}Create Account{% else %}Sign In{% endif %}
        </button>
      </form>
      
      <div class="text-center">
        {% if mode == 'register' %}
        <p class="mb-0">Already have an account? <a href="/login" class="text-success">Sign In</a></p>
        {% else %}
        <p class="mb-0">Don't have an account? <a href="/register" class="text-success">Sign Up</a></p>
        {% endif %}
      </div>
    </div>
    </div>
    
    <script>
      document.getElementById('authForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const submitBtn = document.getElementById('submitBtn');
        const spinner = document.getElementById('spinner');
        const alertContainer = document.getElementById('alert-container');
        
        // Show loading state
        submitBtn.disabled = true;
        spinner.classList.remove('d-none');
        
        const formData = {
          username: document.getElementById('username').value,
          password: document.getElementById('password').value
        };
        
        {% if mode == 'register' %}
        formData.email = document.getElementById('email').value;
        {% endif %}
        
        try {
          const response = await fetch('{% if mode == "register" %}/register{% else %}/login{% endif %}', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData)
          });
          
          const data = await response.json();
          
          if (data.success) {
            window.location.href = data.redirect;
          } else {
            alertContainer.innerHTML = `<div class="alert alert-danger alert-dismissible fade show" role="alert">
              ${data.error}
              <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>`;
          }
        } catch (error) {
          alertContainer.innerHTML = `<div class="alert alert-danger alert-dismissible fade show" role="alert">
            An error occurred. Please try again.
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
          </div>`;
        } finally {
          submitBtn.disabled = false;
          spinner.classList.add('d-none');
        }
      });
    </script>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>
"""

# ---- Basic Dashboard UI ----
INDEX_HTML = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Farm Sensors Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/animate.css@4.1.1/animate.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns@3"></script>
    <style>
      :root {
        --brand: #198754;
        --glass-bg: rgba(255, 255, 255, 0.15);
        --glass-border: rgba(255, 255, 255, 0.2);
        --glass-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
      }
      
      /* Farm background with overlay */
      body {
        background: linear-gradient(135deg, rgba(25, 135, 84, 0.1) 0%, rgba(40, 167, 69, 0.05) 100%),
                    url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 800"><defs><pattern id="farm" patternUnits="userSpaceOnUse" width="120" height="120"><rect width="120" height="120" fill="%23f8f9fa"/><circle cx="20" cy="20" r="2" fill="%23198754" opacity="0.1"/><circle cx="60" cy="40" r="1.5" fill="%2328a745" opacity="0.08"/><circle cx="100" cy="80" r="2.5" fill="%23198754" opacity="0.06"/><path d="M10 100 Q30 90 50 100 T90 100" stroke="%23198754" stroke-width="0.5" fill="none" opacity="0.1"/></pattern></defs><rect width="100%25" height="100%25" fill="url(%23farm)"/></svg>') center/cover;
        background-attachment: fixed;
        min-height: 100vh;
        transition: all 0.3s ease;
      }
      
      /* Glassmorphism cards */
      .card {
        background: var(--glass-bg);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border: 1px solid var(--glass-border);
        box-shadow: var(--glass-shadow);
        border-radius: 16px;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      }
      
      .card:hover {
        transform: translateY(-4px);
        box-shadow: 0 12px 40px 0 rgba(31, 38, 135, 0.5);
      }
      
      /* Glassmorphism navbar */
      .navbar {
        background: rgba(25, 135, 84, 0.9) !important;
        backdrop-filter: blur(20px);
        -webkit-backdrop-filter: blur(20px);
        border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        box-shadow: 0 4px 30px rgba(0, 0, 0, 0.1);
      }
      
      /* Form controls with glass effect */
      .form-control, .btn {
        background: rgba(255, 255, 255, 0.1);
        backdrop-filter: blur(8px);
        border: 1px solid rgba(255, 255, 255, 0.2);
        transition: all 0.3s ease;
      }
      
      .form-control:focus {
        background: rgba(255, 255, 255, 0.2);
        border-color: var(--brand);
        box-shadow: 0 0 0 0.2rem rgba(25, 135, 84, 0.25);
      }
      
      .btn-success {
        background: linear-gradient(135deg, #198754, #28a745);
        border: none;
        box-shadow: 0 4px 15px rgba(25, 135, 84, 0.3);
      }
      
      .btn-success:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(25, 135, 84, 0.4);
      }
      
      /* KPI Cards with enhanced glass effect */
      .kpi-card {
        background: linear-gradient(135deg, rgba(255, 255, 255, 0.2), rgba(255, 255, 255, 0.1));
        backdrop-filter: blur(20px);
        border: 1px solid rgba(255, 255, 255, 0.3);
        transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
      }
      
      .kpi-card:hover {
        transform: translateY(-6px) scale(1.02);
        box-shadow: 0 15px 45px rgba(31, 38, 135, 0.4);
      }
      
      /* Floating animation for icons */
      .floating {
        animation: floating 3s ease-in-out infinite;
      }
      
      @keyframes floating {
        0%, 100% { transform: translateY(0px); }
        50% { transform: translateY(-10px); }
      }
      
      /* Pulse animation for values */
      .pulse-value {
        animation: pulseValue 2s ease-in-out infinite;
      }
      
      @keyframes pulseValue {
        0%, 100% { transform: scale(1); }
        50% { transform: scale(1.05); }
      }
      
      /* Dark mode enhancements */
      [data-bs-theme="dark"] {
        --glass-bg: rgba(18, 26, 31, 0.3);
        --glass-border: rgba(255, 255, 255, 0.1);
        --glass-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.5);
      }
      
      [data-bs-theme="dark"] body {
        background: linear-gradient(135deg, rgba(15, 20, 23, 0.9) 0%, rgba(18, 26, 31, 0.8) 100%),
                    url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 800"><defs><pattern id="farm-dark" patternUnits="userSpaceOnUse" width="120" height="120"><rect width="120" height="120" fill="%23121a1f"/><circle cx="20" cy="20" r="2" fill="%23198754" opacity="0.2"/><circle cx="60" cy="40" r="1.5" fill="%2328a745" opacity="0.15"/><circle cx="100" cy="80" r="2.5" fill="%23198754" opacity="0.1"/><path d="M10 100 Q30 90 50 100 T90 100" stroke="%23198754" stroke-width="0.5" fill="none" opacity="0.2"/></pattern></defs><rect width="100%25" height="100%25" fill="url(%23farm-dark)"/></svg>') center/cover;
      }
      
      [data-bs-theme="dark"] .navbar {
        background: rgba(15, 107, 71, 0.8) !important;
      }
      
      [data-bs-theme="dark"] .form-control {
        background: rgba(255, 255, 255, 0.05);
        color: #dce3e8;
      }
      
      /* Enhanced animations */
      .navbar-brand i { margin-right: .5rem; }
      .border-accent { border-left: .25rem solid var(--brand); padding-left: .5rem; }
      .stat-badge { font-size: .85rem; }
      .footer { color: var(--bs-secondary-color); }
      .form-label { font-weight: 600; }
      
      /* Mobile-first responsive improvements */
      @media (max-width: 768px) {
        .container {
          padding-left: 15px;
          padding-right: 15px;
        }
        
        .navbar-brand {
          font-size: 1.1rem;
        }
        
        .navbar-nav .nav-link {
          padding: 0.5rem 0.75rem;
        }
        
        .display-6 {
          font-size: 2rem !important;
        }
        
        .kpi-card .card-body {
          padding: 1rem 0.75rem;
        }
        
        .kpi-card .fs-1 {
          font-size: 2.5rem !important;
        }
        
        .card-header h6 {
          font-size: 0.9rem;
        }
        
        .btn {
          padding: 0.5rem 1rem;
        }
        
        .form-control {
          padding: 0.5rem 0.75rem;
        }
        
        #chart {
          height: 250px !important;
        }
        
        .table {
          font-size: 0.85rem;
        }
        
        .footer {
          font-size: 0.8rem;
          padding: 1rem 0;
        }
      }
      
      @media (max-width: 576px) {
        .container {
          padding-left: 10px;
          padding-right: 10px;
        }
        
        .navbar {
          padding: 0.5rem 1rem;
        }
        
        .navbar-brand {
          font-size: 1rem;
        }
        
        .navbar-brand span {
          display: none;
        }
        
        .display-6 {
          font-size: 1.5rem !important;
        }
        
        .kpi-card .card-body {
          padding: 0.75rem 0.5rem;
          flex-direction: column;
          text-align: center;
          gap: 0.5rem;
        }
        
        .kpi-card .fs-1 {
          font-size: 2rem !important;
          margin: 0;
        }
        
        .text-uppercase.small {
          font-size: 0.75rem !important;
        }
        
        .card {
          margin-bottom: 1rem;
        }
        
        .row.g-3 {
          --bs-gutter-x: 0.75rem;
          --bs-gutter-y: 0.75rem;
        }
        
        .btn-group-vertical .btn {
          font-size: 0.85rem;
        }
        
        #chart {
          height: 200px !important;
        }
        
        .table-responsive {
          font-size: 0.8rem;
        }
        
        .alert {
          padding: 0.5rem 0.75rem;
          font-size: 0.85rem;
        }
      }
      
      /* Landscape mobile optimization */
      @media (max-width: 896px) and (orientation: landscape) {
        .kpi-card .card-body {
          padding: 0.5rem;
        }
        
        .display-6 {
          font-size: 1.25rem !important;
        }
        
        .kpi-card .fs-1 {
          font-size: 1.5rem !important;
        }
        
        #chart {
          height: 180px !important;
        }
      }
      
      /* Tablet optimization */
      @media (min-width: 768px) and (max-width: 1024px) {
        .container {
          max-width: 100%;
          padding-left: 20px;
          padding-right: 20px;
        }
        
        .display-6 {
          font-size: 2.25rem !important;
        }
        
        #chart {
          height: 300px !important;
        }
      }
      
      /* Touch-friendly improvements */
      @media (hover: none) and (pointer: coarse) {
        .btn {
          min-height: 44px;
          padding: 0.75rem 1rem;
        }
        
        .form-control {
          min-height: 44px;
          padding: 0.75rem;
        }
        
        .card {
          transition: none;
        }
        
        .card:hover {
          transform: none;
        }
        
        .kpi-card:hover {
          transform: none;
        }
        
        .btn-success:hover {
          transform: none;
        }
      }
      
      /* Smooth transitions for theme changes */
      html, body, .card, .navbar, .btn, .form-control { 
        transition: background-color .3s ease, color .3s ease, border-color .3s ease, transform .3s ease; 
      }
      
      /* Loading spinners with glass effect */
      .loading { 
        display: flex; 
        align-items: center; 
        gap: .5rem; 
        color: var(--bs-secondary-color);
        background: rgba(255, 255, 255, 0.1);
        backdrop-filter: blur(8px);
        padding: 1rem;
        border-radius: 12px;
        border: 1px solid rgba(255, 255, 255, 0.1);
      }
      
      /* Staggered fade-in animation */
      .fade-in { animation: fadeIn .6s ease-out; }
      @keyframes fadeIn { 
        from { opacity: 0; transform: translateY(20px); } 
        to { opacity: 1; transform: translateY(0); } 
      }
      
      /* Chart container enhancement */
      #chart {
        border-radius: 12px;
        background: rgba(255, 255, 255, 0.05);
      }
      
      /* Alert enhancements */
      .alert {
        background: rgba(255, 255, 255, 0.15);
        backdrop-filter: blur(12px);
        border: 1px solid rgba(255, 255, 255, 0.2);
        border-radius: 12px;
      }
    </style>
  </head>
  <body class="bg-light" id="pageBody">
    <nav class="navbar navbar-expand-lg bg-success navbar-dark mb-3" id="topnav">
      <div class="container-fluid">
        <a class="navbar-brand d-flex align-items-center" href="#">
          <i class="bi bi-flower1"></i>
          <span>Farm Dashboard</span>
        </a>
        <button class="navbar-toggler d-lg-none" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
          <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
          <div class="d-flex gap-2 ms-auto align-items-center flex-wrap">
            <span class="text-light me-2 d-none d-md-inline">
              <i class="bi bi-person-circle me-1"></i>
              <span class="d-none d-lg-inline">{{ user.username }}</span>
            </span>
            <div class="d-flex gap-2 flex-wrap">
              <button id="themeToggle" class="btn btn-outline-light btn-sm" type="button">
                <i class="bi bi-moon-stars me-1"></i><span class="d-none d-md-inline">Dark</span>
              </button>
              <a href="/logout" class="btn btn-outline-light btn-sm">
                <i class="bi bi-box-arrow-right me-1"></i><span class="d-none d-md-inline">Logout</span>
              </a>
            </div>
          </div>
        </div>
      </div>
    </nav>

    <div class="container">
      <div id="alerts"></div>

      <div class="card mb-3">
        <div class="card-body">
          <form id="query-form" class="row g-3">
            <div class="col-12 col-sm-6 col-lg-4">
              <label class="form-label">Sensor</label>
              <input type="text" class="form-control" id="sensor" placeholder="e.g. soil_moisture" list="sensor-list" required>
              <datalist id="sensor-list"></datalist>
            </div>
            <div class="col-12 col-sm-6 col-lg-3">
              <label class="form-label">Location (optional)</label>
              <input type="text" class="form-control" id="location" placeholder="e.g. field-1" list="location-list">
              <datalist id="location-list"></datalist>
            </div>
            <div class="col-6 col-sm-4 col-lg-2">
              <label class="form-label">Hours</label>
              <input type="number" class="form-control" id="hours" value="24" min="1" max="720">
            </div>
            <div class="col-6 col-sm-8 col-lg-3 d-flex align-items-end">
              <button type="submit" class="btn btn-success w-100">Load Chart</button>
            </div>
          </form>
        </div>
      </div>

      <!-- KPI Cards -->
      <div class="row g-3 mb-4">
        <div class="col-12 col-sm-6 col-lg-4">
          <div class="card kpi-card border-0 animate__animated" id="kpi-moisture-card">
            <div class="card-body d-flex align-items-center justify-content-between">
              <div class="flex-grow-1">
                <div class="text-uppercase small text-muted fw-bold">Soil Moisture</div>
                <div class="display-6 fw-semibold pulse-value" id="kpi-soil_moisture">--</div>
              </div>
              <i class="bi bi-droplet-half fs-1 text-success floating flex-shrink-0"></i>
            </div>
          </div>
        </div>
        <div class="col-12 col-sm-6 col-lg-4">
          <div class="card kpi-card border-0 animate__animated" id="kpi-temperature-card">
            <div class="card-body d-flex align-items-center justify-content-between">
              <div class="flex-grow-1">
                <div class="text-uppercase small text-muted fw-bold">Temperature</div>
                <div class="display-6 fw-semibold pulse-value" id="kpi-temperature">--</div>
              </div>
              <i class="bi bi-thermometer-half fs-1 text-danger floating flex-shrink-0" style="animation-delay: 0.5s;"></i>
            </div>
          </div>
        </div>
        <div class="col-12 col-sm-12 col-lg-4">
          <div class="card kpi-card border-0 animate__animated" id="kpi-humidity-card">
            <div class="card-body d-flex align-items-center justify-content-between">
              <div class="flex-grow-1">
                <div class="text-uppercase small text-muted fw-bold">Humidity</div>
                <div class="display-6 fw-semibold pulse-value" id="kpi-humidity">--</div>
              </div>
              <i class="bi bi-wind fs-1 text-primary floating flex-shrink-0" style="animation-delay: 1s;"></i>
            </div>
          </div>
        </div>
      </div>

      <div class="row g-3">
        <div class="col-12 col-xl-4 order-2 order-xl-1">
          <div class="card h-100">
            <div class="card-header bg-success text-white">
              <h6 class="mb-0">📊 Latest Readings</h6>
            </div>
            <div class="card-body">
              <div id="latest-readings" class="small loading">
                <div class="spinner-border spinner-border-sm text-success" role="status"></div>
                <span>Loading latest readings...</span>
              </div>
            </div>
          </div>
        </div>
        <div class="col-12 col-xl-8 order-1 order-xl-2">
          <div class="card h-100">
            <div class="card-header bg-success text-white">
              <h6 class="mb-0">📈 Time Series</h6>
            </div>
            <div class="card-body">
              <div id="chart-loading" class="loading mb-2">
                <div class="spinner-border spinner-border-sm text-success" role="status"></div>
                <span>Preparing chart...</span>
              </div>
              <div class="position-relative" style="height: 300px;">
                <canvas id="chart" class="d-none w-100 h-100"></canvas>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="row g-3 mt-3">
        <div class="col-12">
          <div class="card">
            <div class="card-header bg-success text-white">
              <h6 class="mb-0">📋 24-Hour Statistics</h6>
            </div>
            <div class="card-body">
              <div id="stats-table" class="table-responsive">
                <div class="loading">
                  <div class="spinner-border spinner-border-sm text-success" role="status"></div>
                  <span>Loading statistics...</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div class="row mt-4">
        <div class="col-12">
          <div class="text-center small footer">
            <i class="bi bi-activity me-1"></i>
            Live farm metrics dashboard · Built with Flask, Bootstrap, and Chart.js
          </div>
        </div>
      </div>
    </div>

    <script>
      // Theme management (Bootstrap 5.3 data-bs-theme)
      (function() {
        const stored = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-bs-theme', stored);
        const btn = () => document.getElementById('themeToggle');
        const updateBtn = () => {
          const theme = document.documentElement.getAttribute('data-bs-theme');
          if (btn()) btn().innerHTML = theme === 'dark'
            ? '<i class="bi bi-sun me-1"></i><span class="d-none d-sm-inline">Light</span>'
            : '<i class="bi bi-moon-stars me-1"></i><span class="d-none d-sm-inline">Dark</span>';
        }
        document.addEventListener('DOMContentLoaded', () => {
          updateBtn();
          if (btn()) btn().addEventListener('click', () => {
            const current = document.documentElement.getAttribute('data-bs-theme') || 'light';
            const next = current === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-bs-theme', next);
            localStorage.setItem('theme', next);
            updateBtn();
          });
        });
      })();
      async function checkHealth() {
        try {
          const res = await fetch('/api/health');
          const data = await res.json();
          if (data.status !== 'ok') {
            showAlert('warning', 'MongoDB connection degraded. ' + (data.mongo || ''));
          }
        } catch (e) {
          showAlert('danger', 'Health check failed: ' + e);
        }
      }

      function showAlert(type, message) {
        const alerts = document.getElementById('alerts');
        alerts.innerHTML = `<div class="alert alert-${type} alert-dismissible fade show" role="alert">${message}<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button></div>`;
      }

      async function loadSummary() {
        try {
          const res = await fetch('/api/summary');
          const data = await res.json();
          
          // Update latest readings
          const container = document.getElementById('latest-readings');
          if (data.latest && data.latest.length) {
            container.innerHTML = data.latest.map(r => {
              const ts = r.timestamp ? new Date(r.timestamp.$date).toLocaleString() : '-';
              const loc = r.location || 'N/A';
              return `<div class="mb-2 p-2 border-start border-success border-3">
                        <strong>${r.sensor}</strong> (${loc})<br>
                        <span class="h5 text-success">${r.value} ${r.unit || ''}</span><br>
                        <small class="text-muted">${ts}</small>
                      </div>`
            }).join('');
          } else {
            container.innerHTML = '<div class="text-muted">No data available</div>';
          }

          // Update KPIs based on common sensors (if present)
          const latestMap = Object.fromEntries((data.latest || []).map(r => [r.sensor, r]));
          updateKPI('soil_moisture', latestMap['soil_moisture']);
          updateKPI('temperature', latestMap['temperature']);
          updateKPI('humidity', latestMap['humidity']);

          // Update stats table
          const statsContainer = document.getElementById('stats-table');
          if (data.stats_24h && data.stats_24h.length) {
            const tableHtml = `
              <table class="table table-sm">
                <thead>
                  <tr>
                    <th>Sensor</th>
                    <th>Count</th>
                    <th>Min</th>
                    <th>Max</th>
                    <th>Average</th>
                  </tr>
                </thead>
                <tbody>
                  ${data.stats_24h.map(s => `
                    <tr>
                      <td><strong>${s.sensor}</strong></td>
                      <td>${s.count}</td>
                      <td>${s.min?.toFixed(2) || '-'}</td>
                      <td>${s.max?.toFixed(2) || '-'}</td>
                      <td>${s.avg?.toFixed(2) || '-'}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            `;
            statsContainer.innerHTML = tableHtml;
          } else {
            statsContainer.innerHTML = '<div class="text-muted">No statistics available</div>';
          }
        } catch (e) {
          document.getElementById('latest-readings').innerHTML = '<div class="text-danger">Error loading summary</div>';
          document.getElementById('stats-table').innerHTML = '<div class="text-danger">Error loading statistics</div>';
        }
      }

      let chart;
      function ensureChart() {
        if (!chart) {
          const ctx = document.getElementById('chart');
          chart = new Chart(ctx, {
            type: 'line',
            data: { 
              labels: [], 
              datasets: [{ 
                label: 'Value', 
                data: [], 
                borderColor: '#198754', 
                backgroundColor: 'rgba(25, 135, 84, 0.1)',
                tension: 0.2,
                fill: true,
                pointRadius: 0,
                pointHoverRadius: 4
              }] 
            },
            options: { 
              responsive: true, 
              maintainAspectRatio: false,
              animation: {
                duration: 600,
                easing: 'easeOutQuart'
              },
              interaction: {
                intersect: false,
                mode: 'index'
              },
              scales: { 
                x: { 
                  type: 'time', 
                  time: { 
                    unit: 'hour',
                    displayFormats: {
                      hour: 'MMM dd HH:mm'
                    }
                  },
                  ticks: {
                    maxTicksLimit: window.innerWidth < 768 ? 4 : 8
                  }
                },
                y: {
                  beginAtZero: false,
                  ticks: {
                    maxTicksLimit: window.innerWidth < 768 ? 5 : 8
                  }
                }
              },
              plugins: {
                legend: {
                  display: true,
                  position: window.innerWidth < 768 ? 'bottom' : 'top'
                },
                tooltip: {
                  mode: 'index',
                  intersect: false,
                  backgroundColor: 'rgba(0, 0, 0, 0.8)',
                  titleColor: 'white',
                  bodyColor: 'white',
                  borderColor: '#198754',
                  borderWidth: 1
                }
              }
            }
          });
          // Reveal chart canvas
          document.getElementById('chart-loading').classList.add('d-none');
          ctx.classList.remove('d-none');
          ctx.classList.add('animate__animated','animate__fadeIn');
        }
      }

      // Populate sensor and location lists
      async function loadSensors() {
        try {
          const res = await fetch('/api/sensors');
          const data = await res.json();
          const sList = document.getElementById('sensor-list');
          const lList = document.getElementById('location-list');
          if (sList && data.sensors) {
            sList.innerHTML = data.sensors.map(s => `<option value="${s}"></option>`).join('');
          }
          if (lList && data.locations) {
            lList.innerHTML = data.locations.map(l => `<option value="${l}"></option>`).join('');
          }
        } catch (e) { /* ignore UI hint errors */ }
      }

      // KPI helpers with thresholds
      function updateKPI(key, reading) {
        const el = document.getElementById('kpi-' + key);
        const card = document.getElementById('kpi-' + (key === 'soil_moisture' ? 'moisture' : key) + '-card');
        if (!el || !card) return;
        if (!reading) { el.textContent = '--'; card.classList.remove('animate__pulse'); return; }
        const value = reading.value; const unit = reading.unit || '';
        el.textContent = `${value} ${unit}`;
        // thresholds (example defaults)
        let status = 'normal';
        if (key === 'soil_moisture') {
          if (value < 15) status = 'danger'; else if (value < 25) status = 'warn';
        } else if (key === 'temperature') {
          if (value > 40) status = 'danger'; else if (value > 35) status = 'warn';
        } else if (key === 'humidity') {
          if (value < 25) status = 'danger'; else if (value < 35) status = 'warn';
        }
        card.classList.remove('border-danger','border-warning','border-0','animate__pulse');
        if (status === 'danger') { card.classList.add('border','border-danger','animate__animated','animate__pulse'); }
        else if (status === 'warn') { card.classList.add('border','border-warning'); }
        else { card.classList.add('border-0'); }
      }

      async function loadSeries(sensor, hours, location) {
        try {
          const params = new URLSearchParams({ sensor, hours: String(hours) });
          if (location) params.set('location', location);
          const res = await fetch('/api/timeseries?' + params.toString());
          const data = await res.json();
          
          if (data.error) {
            showAlert('danger', 'API Error: ' + data.error);
            return;
          }

          ensureChart();
          const labels = data.map(d => new Date(d.timestamp.$date));
          const values = data.map(d => d.value);
          
          chart.data.labels = labels;
          chart.data.datasets[0].data = values;
          chart.data.datasets[0].label = `${sensor} ${data[0]?.unit || ''}`;
          chart.update('active');

          if (data.length === 0) {
            showAlert('info', `No data found for sensor "${sensor}" in the last ${hours} hours.`);
          }
        } catch (e) {
          showAlert('danger', 'Failed to load series: ' + e);
        }
      }

      document.getElementById('query-form').addEventListener('submit', (e) => {
        e.preventDefault();
        const sensor = document.getElementById('sensor').value.trim();
        const location = document.getElementById('location').value.trim();
        const hours = parseInt(document.getElementById('hours').value, 10) || 24;
        if (sensor) loadSeries(sensor, hours, location);
      });

      // Handle responsive chart updates
      function updateChartResponsiveness() {
        if (chart) {
          const isMobile = window.innerWidth < 768;
          chart.options.scales.x.ticks.maxTicksLimit = isMobile ? 4 : 8;
          chart.options.scales.y.ticks.maxTicksLimit = isMobile ? 5 : 8;
          chart.options.plugins.legend.position = isMobile ? 'bottom' : 'top';
          chart.update('none');
        }
      }

      // Initialize with staggered animations
      document.addEventListener('DOMContentLoaded', () => {
        // Animate KPI cards first
        document.querySelectorAll('.kpi-card').forEach((c, i) => {
          setTimeout(() => c.classList.add('animate__fadeInUp'), 200 + (i * 150));
        });
        
        // Then animate other cards
        document.querySelectorAll('.card:not(.kpi-card)').forEach((c, i) => {
          setTimeout(() => c.classList.add('animate__animated','animate__fadeInUp'), 800 + (i * 200));
        });
        
        // Add floating animation to navbar brand icon
        setTimeout(() => {
          const brandIcon = document.querySelector('.navbar-brand i');
          if (brandIcon) brandIcon.classList.add('floating');
        }, 1500);
        
        // Handle window resize for responsive chart
        window.addEventListener('resize', updateChartResponsiveness);
      });
      
      checkHealth();
      loadSummary();
      loadSensors();
      
      // Auto-refresh summary every minute
      setInterval(loadSummary, 60000);
    </script>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>
"""


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template_string(INDEX_HTML, user=current_user)


if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=DEBUG)