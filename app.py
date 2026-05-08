# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import time
import yaml
import logging
import random
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, make_response, session, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.middleware.proxy_fix import ProxyFix
# Proxy imports removed - no separate lab applications

# Log shipping for SIEM integration
from log_shipping import bbwaf_logging_middleware, log_auth_event, log_concierge_event
from auth_traffic_generator import start_auth_generator

# OTel poll-based metrics (Prometheus scrape endpoint on port 9464)
from observability.metrics import init_metrics

# Configure logging
logging.basicConfig(level=logging.INFO)

# Create SQLAlchemy instance (compatible with older versions)
# Using try/except for compatibility with different SQLAlchemy versions
try:
    from sqlalchemy.orm import DeclarativeBase
    class Base(DeclarativeBase):
        pass
    db = SQLAlchemy(model_class=Base)
except ImportError:
    # Fallback for older SQLAlchemy versions
    db = SQLAlchemy()

# Create the main app
app = Flask(__name__)

# Intentionally vulnerable: Hardcoded secret key (CKV3_SAST_152)
app.secret_key = os.environ.get("SESSION_SECRET", "hardcoded-secret-key-12345")

app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///gocortexbrokenbank.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False  # Suppress Flask-SQLAlchemy warning

# Initialize the app with the extension
db.init_app(app)

# Application version
APP_VERSION = "1.5.0"

# OTel metrics - start Prometheus scrape endpoint on port 9464
init_metrics(port=9464)

# Flask HTTP instrumentation - record per-request counts and durations.
# Skips the /metrics path itself to avoid self-scrape noise in the output.
@app.before_request
def _metrics_before_request():
    from observability import metrics as _m
    if request.path != "/metrics" and _m.http_requests is not None:
        g._metrics_start = time.time()

@app.after_request
def _metrics_after_request(response):
    from observability import metrics as _m
    start = getattr(g, "_metrics_start", None)
    if start is not None and _m.http_requests is not None:
        duration = time.time() - start
        labels = {
            "method": request.method,
            "endpoint": request.endpoint or request.path,
            "status_code": str(response.status_code),
        }
        _m.http_requests.add(1, labels)
        _m.http_request_duration.record(
            duration,
            {"method": request.method, "endpoint": request.endpoint or request.path},
        )
    return response

# Testing URLs for cybersecurity validation purposes only - these are fictitious endpoints
# used by automated security scanners to validate URL filtering and threat detection capabilities
TEST_MALWARE_URL = "https://urlfiltering.paloaltonetworks.com/test-malware"  # Official Palo Alto test endpoint
TEST_C2_DOMAIN = "c2.sigre.xyz"  # Simulated command and control domain for testing
TEST_BOTNET_DOMAIN = "botnet.sigre.xyz"  # Test botnet domain for security validation

# Load localisation config
def load_localisation():
    locale_code = os.environ.get("LOCALE", "en")
    
    locale_files = {
        "en": "config/localise.yaml",
        "kr": "config/localise.yaml.kr"
    }
    
    locale_file = locale_files.get(locale_code, "config/localise.yaml")
    
    if locale_code not in locale_files:
        logging.warning(f"Unknown LOCALE '{locale_code}', defaulting to English (en)")
    
    try:
        with open(locale_file, 'r') as file:
            logging.info(f"Loaded localisation from {locale_file}")
            return yaml.safe_load(file)
    except FileNotFoundError:
        logging.warning(f"Locale file {locale_file} not found, falling back to config/localise.yaml")
        try:
            with open('config/localise.yaml', 'r') as file:
                return yaml.safe_load(file)
        except FileNotFoundError:
            logging.error("Default localisation file not found")
            return {}

localisation = load_localisation()

# Setup Mars Banking Initiative repository (Exposed Git Repository)
def setup_mars_repo():
    """
    Create the Mars Banking Initiative git repository for security testing.
    Implements the Exposed Local Git Repository capability.
    Creates realistic commit history simulating development progression.
    """
    import subprocess
    import shutil
    import os
    from pathlib import Path
    from datetime import datetime, timedelta
    
    target = Path(__file__).parent / "data" / "projects" / "mars-banking-initiative"
    template = Path(__file__).parent / "vulnerable_data" / "mars_banking_initiative"
    
    # Skip if already exists with .git directory
    if (target / ".git").exists():
        return
    
    # Commit history simulating realistic development
    commits = [
        {"msg": "Initial commit - Project Ares scaffolding", "author": "Eleanor Blackwood", "email": "eleanor.blackwood@gocortex.io", "days": 180, "files": ["README.md", "requirements.txt", ".gitignore"]},
        {"msg": "Add SpaceATM core module with dispensing logic", "author": "Marcus Chen", "email": "marcus.chen@gocortex.io", "days": 150, "files": ["src/__init__.py", "src/space_atm.py"]},
        {"msg": "Implement Mars Gateway relay system", "author": "Marcus Chen", "email": "marcus.chen@gocortex.io", "days": 120, "files": ["src/mars_gateway.py"]},
        {"msg": "Add orbital authentication for spacesuit biometrics", "author": "Priya Sharma", "email": "priya.sharma@gocortex.io", "days": 90, "files": ["src/orbital_auth.py"]},
        {"msg": "Implement quantum ledger with QDCP", "author": "Eleanor Blackwood", "email": "eleanor.blackwood@gocortex.io", "days": 60, "files": ["src/quantum_ledger.py"]},
        {"msg": "Add production configuration (DO NOT COMMIT - oops)", "author": "Marcus Chen", "email": "marcus.chen@gocortex.io", "days": 45, "files": ["config/production.yaml", "config/.env.production"]},
        {"msg": "Add credentials file for deployment automation", "author": "Simon Sigre", "email": "simon@simonsigre.com", "days": 30, "files": ["config/credentials.json"]},
        {"msg": "Add SSH keys for Mars Gateway deployment", "author": "Marcus Chen", "email": "marcus.chen@gocortex.io", "days": 25, "files": [".ssh/id_rsa", ".ssh/id_rsa.pub"]},
        {"msg": "Add financial projections and patent strategy docs", "author": "Simon Sigre", "email": "simon@simonsigre.com", "days": 15, "files": ["docs/FINANCIAL_PROJECTIONS.md", "docs/PATENT_STRATEGY.md"]},
    ]
    
    try:
        # Create target directory
        target.mkdir(parents=True, exist_ok=True)
        
        # Copy template files
        if template.exists():
            for item in template.iterdir():
                dest = target / item.name
                if item.is_dir():
                    if dest.exists():
                        shutil.rmtree(dest)
                    shutil.copytree(item, dest)
                else:
                    shutil.copy2(item, dest)
        
        # Initialise git repository
        subprocess.run(["git", "init"], cwd=target, capture_output=True)
        subprocess.run(["git", "config", "user.email", "ares@gocortex.io"], cwd=target, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Ares Build System"], cwd=target, capture_output=True)
        
        # Create commits with realistic history
        for commit in commits:
            commit_date = datetime.now() - timedelta(days=commit["days"])
            date_str = commit_date.strftime("%Y-%m-%dT%H:%M:%S")
            
            # Add files for this commit
            for file_path in commit["files"]:
                full_path = target / file_path
                if full_path.exists():
                    subprocess.run(["git", "add", file_path], cwd=target, capture_output=True)
            
            # Create commit with author and date
            env = os.environ.copy()
            env.update({
                "GIT_AUTHOR_NAME": commit["author"],
                "GIT_AUTHOR_EMAIL": commit["email"],
                "GIT_AUTHOR_DATE": date_str,
                "GIT_COMMITTER_NAME": commit["author"],
                "GIT_COMMITTER_EMAIL": commit["email"],
                "GIT_COMMITTER_DATE": date_str
            })
            subprocess.run(["git", "commit", "-m", commit["msg"], "--allow-empty"], cwd=target, capture_output=True, env=env)
        
        logging.info(f"Mars Banking Initiative repository created at {target} with {len(commits)} commits")
    except Exception as e:
        logging.warning(f"Failed to setup Mars repo: {e}")

# Initialise Mars repo on startup
try:
    setup_mars_repo()
except Exception as e:
    logging.warning(f"Mars repo setup skipped: {e}")

# Apply BBWAF logging middleware for SIEM integration
bbwaf_logging_middleware(app)

# Make localisation available in templates
@app.context_processor
def inject_localisation():
    return dict(locale=localisation, app_version=APP_VERSION)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/disclaimer')
def disclaimer():
    return render_template('disclaimer.html')

# Mars Banking Initiative Concierge - intentionally vulnerable LLM chatbot
# Demonstrates OWASP LLM Top 10: LLM01 Prompt Injection, LLM02 Insecure Output
# Handling, LLM06 Sensitive Information Disclosure, LLM08 Excessive Agency.
from chatbot import concierge as _concierge

# Pre-warm the SmolLM2 GGUF in a background thread so the first
# /concierge/chat request does not pay the multi-second cold-load
# latency. Without this the live demo has a visible "tell": injection
# prompts (which used to short-circuit the LLM) returned instantly
# while the first safe banking turn took 10+ seconds, breaking the
# illusion that the model is actually being attacked.
_concierge.start_warmup()

CONCIERGE_MODEL_NAME = os.environ.get(
    "CONCIERGE_MODEL_NAME", "SmolLM2-135M-Instruct GGUF Q4_K_M"
)

@app.route('/concierge')
def concierge_page():
    """Render the Mars Banking Initiative Concierge chat page."""
    return render_template(
        'concierge.html',
        model_name=CONCIERGE_MODEL_NAME,
        context_count=len(_concierge.get_extra_context()),
        concierge_disabled=_concierge.is_disabled(),
        concierge_disabled_reason=_concierge.disabled_reason(),
        concierge_disabled_message=_concierge.disabled_message(),
    )

def _concierge_session_id():
    """Return a stable session id for SIEM correlation, minting one on first use."""
    sid = session.get('concierge_session_id')
    if not sid:
        import uuid as _uuid
        sid = _uuid.uuid4().hex
        session['concierge_session_id'] = sid
    return sid


def _concierge_context_labels():
    return [label for label, _body in _concierge.get_extra_context()]


@app.route('/concierge/chat', methods=['POST'])
def concierge_chat():
    """Intentionally vulnerable chat endpoint.

    No input sanitisation, no output filter, no allow-list, no rate limit.
    Logs full prompts and responses to stdout for SIEM training, and ships
    one prompt event and one response event per turn (correlated by
    turn_id) to the netbank_concierge XSIAM stream so a prompt-injection
    detection ruleset has something to match on.
    """
    user_message = request.form.get('message', '') or request.values.get('message', '')
    if not user_message:
        return "No message provided", 400
    logging.info("CONCIERGE REQUEST remote=%s ua=%s message=%r",
                 request.remote_addr, request.headers.get('User-Agent', ''),
                 user_message)

    import uuid as _uuid
    turn_id = _uuid.uuid4().hex
    session_id = _concierge_session_id()
    context_labels = _concierge_context_labels()

    effective_model_name = (
        "disabled" if _concierge.is_disabled() else CONCIERGE_MODEL_NAME
    )

    log_concierge_event(
        "prompt", request,
        session_id=session_id, turn_id=turn_id,
        model_name=effective_model_name,
        prompt_text=user_message,
        context_document_count=len(context_labels),
        context_document_labels=context_labels,
    )

    if _concierge.is_disabled():
        response_text = _concierge.disabled_message()
        response_path = "disabled"
    else:
        response_text, response_path = _concierge.generate(user_message)

    # Re-read context labels in case generate() (or the model) mutated state.
    context_labels = _concierge_context_labels()
    log_concierge_event(
        "response", request,
        session_id=session_id, turn_id=turn_id,
        model_name=effective_model_name,
        response_text=response_text,
        response_path=response_path,
        context_document_count=len(context_labels),
        context_document_labels=context_labels,
    )

    return response_text, 200, {'Content-Type': 'text/plain; charset=utf-8'}

@app.route('/concierge/load_url', methods=['POST'])
def concierge_load_url():
    """Indirect prompt-injection sink: fetch a URL and add to context.

    No URL validation, no SSRF guard, no sanitisation of fetched content.
    """
    url = request.form.get('url', '')
    if not url:
        return "No url provided", 400
    import requests as _req
    try:
        resp = _req.get(url, verify=False, timeout=10)
        body = resp.text[:8000]
        _concierge.add_context_document(url, body)

        import uuid as _uuid
        context_labels = _concierge_context_labels()
        log_concierge_event(
            "context_loaded", request,
            session_id=_concierge_session_id(),
            turn_id=_uuid.uuid4().hex,
            model_name=CONCIERGE_MODEL_NAME,
            document_label=url,
            source_url=url,
            body_preview=body,
            body_length=len(body),
            context_document_count=len(context_labels),
            context_document_labels=context_labels,
        )
        return f"Loaded {len(body)} characters from {url} into Concierge context"
    except Exception as exc:
        return f"Failed to load {url}: {exc}", 502

@app.route('/concierge/load_text', methods=['POST'])
def concierge_load_text():
    """Indirect prompt-injection sink: accept raw text into context."""
    label = request.form.get('label', 'uploaded-document')
    body = request.form.get('body', '')
    if not body:
        return "No body provided", 400
    truncated = body[:16000]
    _concierge.add_context_document(label, truncated)

    import uuid as _uuid
    context_labels = _concierge_context_labels()
    log_concierge_event(
        "context_loaded", request,
        session_id=_concierge_session_id(),
        turn_id=_uuid.uuid4().hex,
        model_name=CONCIERGE_MODEL_NAME,
        document_label=label,
        body_preview=truncated,
        body_length=len(truncated),
        context_document_count=len(context_labels),
        context_document_labels=context_labels,
    )
    return f"Added document {label!r} ({len(body)} chars) to Concierge context"

# Banking Pages
@app.route('/netbank')
def netbank():
    """Personal netbank page with session-based balance and transactions"""
    is_new_session = 'account_balance' not in session
    
    if is_new_session:
        session['account_balance'] = round(random.uniform(150, 8500000), 2)
        session['account_number'] = f"{random.randint(10000000, 99999999)}"
        session['sort_code'] = f"{random.randint(10, 99)}-{random.randint(10, 99)}-{random.randint(10, 99)}"
    
    # Log authentication event for SIEM
    username = session.get('username', f"user_{session['account_number'][-4:]}")
    log_auth_event(username, "success", request, simulated=False)
    
    balance = session['account_balance']
    account_number = session['account_number']
    sort_code = session['sort_code']
    
    tier = 'high_balance' if balance > 100000 else 'low_balance'
    transactions_data = localisation['pages']['netbank']['transactions']['tiers'][tier]
    
    total_transaction_amount = sum(float(txn['amount']) for txn in transactions_data)
    opening_balance = balance - total_transaction_amount
    
    running_balance = opening_balance
    transactions = []
    for txn in transactions_data:
        amount = float(txn['amount'])
        running_balance += amount
        
        transactions.append({
            'date': txn['date'],
            'description': txn['description'],
            'amount': abs(amount),
            'type': txn['type'],
            'balance': round(running_balance, 2)
        })
    
    return render_template('netbank.html', 
                         balance=balance,
                         account_number=account_number,
                         sort_code=sort_code,
                         transactions=transactions)

@app.route('/business')
def business():
    """Business banking services page"""
    return render_template('business.html')

@app.route('/investments')
def investments():
    """Investment services page"""
    return render_template('investments.html')

@app.route('/digital')
def digital():
    """Digital banking services page"""
    return render_template('digital.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Account signup page with no verification"""
    if request.method == 'POST':
        new_account_number = f"{random.randint(10000000, 99999999)}"
        new_sort_code = f"{random.randint(10, 99)}-{random.randint(10, 99)}-{random.randint(10, 99)}"
        account_type = request.form.get('account_type', 'personal')
        
        # Log signup event for SIEM
        username = request.form.get('full_name', f"user_{new_account_number[-4:]}")
        log_auth_event(username, "signup_success", request, simulated=False)
        
        return render_template('signup.html', 
                             success=True,
                             account_number=new_account_number,
                             sort_code=new_sort_code,
                             account_type=account_type)
    
    return render_template('signup.html', success=False)

# Labs route removed - application contains built-in vulnerabilities

# Intentionally vulnerable: Debug mode enabled in production (CKV3_SAST_96)
@app.route('/debug')
def debug_info():
    """Intentionally vulnerable debug endpoint"""
    import sys
    import os
    debug_data = {
        'python_path': sys.path,
        'environment': {k: str(v) for k, v in os.environ.items()},
        'request_headers': dict(request.headers),
        'app_config': {k: str(v) for k, v in app.config.items()}
    }
    return debug_data

# Vulnerable logging (CKV3_SAST_62)
@app.route('/log/<message>')
def log_message(message):
    """Intentionally vulnerable logging endpoint"""
    logging.info(f"User message: {message}")  # Direct user input logging
    return f"Logged message: {message}"

# Intentionally vulnerable: SQL injection (CKV3_SAST_51)
@app.route('/search')
def search():
    """Intentionally vulnerable search endpoint"""
    query = request.args.get('q', '')
    if query:
        # Vulnerable SQL query construction
        sql = f"SELECT * FROM users WHERE name LIKE '%{query}%'"
        return f"Search query executed: {sql}"
    return "Search endpoint - provide ?q=searchterm"

# Intentionally vulnerable: XSS (CKV3_SAST_69)
@app.route('/comment')
def comment():
    """Intentionally vulnerable comment endpoint"""
    user_comment = request.args.get('comment', '')
    if user_comment:
        # Vulnerable: Direct output without sanitisation
        return f"<h3>Your comment:</h3><p>{user_comment}</p>"
    return "Comment endpoint - provide ?comment=yourcomment"

# Intentionally vulnerable: LDAP injection (CKV3_SAST_61)
@app.route('/ldap')
def ldap_search():
    """Intentionally vulnerable LDAP search endpoint"""
    username = request.args.get('user', '')
    if username:
        # Vulnerable LDAP query construction
        ldap_filter = f"(uid={username})"
        return f"LDAP search filter: {ldap_filter}"
    return "LDAP endpoint - provide ?user=username"

# Intentionally vulnerable: Path traversal (CKV3_SAST_86)
@app.route('/file')
def read_file():
    """Intentionally vulnerable file reading endpoint"""
    filename = request.args.get('name', '')
    if filename:
        # Vulnerable file path construction
        file_path = f"/app/data/{filename}"
        return f"Reading file: {file_path}"
    return "File endpoint - provide ?name=filename"

# Intentionally vulnerable: Weak cryptography (CKV3_SAST_55)
@app.route('/hash')
def hash_password():
    """Intentionally vulnerable password hashing endpoint"""
    password = request.args.get('password', '')
    if password:
        # Vulnerable: Using MD5 for password hashing
        import hashlib
        hash_value = hashlib.md5(password.encode()).hexdigest()
        return f"MD5 hash: {hash_value}"
    return "Hash endpoint - provide ?password=yourpassword"

# Intentionally vulnerable: Insecure deserialization (CKV3_SAST_58)
@app.route('/deserialize')
def deserialize_data():
    """Intentionally vulnerable deserialization endpoint"""
    data = request.args.get('data', '')
    if data:
        # Vulnerable: Unsafe deserialization
        import pickle
        import base64
        try:
            decoded = base64.b64decode(data)
            result = pickle.loads(decoded)
            return f"Deserialized: {result}"
        except:
            return "Invalid data format"
    return "Deserialize endpoint - provide ?data=base64encodedpickle"

# Intentionally vulnerable: SSRF (CKV3_SAST_189)
@app.route('/fetch')
def fetch_url():
    """Intentionally vulnerable SSRF endpoint - TRULY EXPLOITABLE"""
    url = request.args.get('url', '')
    if url:
        # Vulnerable: Direct URL request without validation
        import requests
        try:
            response = requests.get(url, verify=False, timeout=5)  # Also CKV3_SAST_186
            # TRULY EXPLOITABLE: Return actual fetched content to prove SSRF works
            return f"Fetched content from: {url}\n\n{response.text[:4000]}"
        except Exception as e:
            return f"Failed to fetch: {url} - {e}"
    return "Fetch endpoint - provide ?url=http://example.com"

# Intentionally vulnerable: XXE (CKV3_SAST_50, CKV3_SAST_90)
@app.route('/xml', methods=['POST'])
def parse_xml():
    """Intentionally vulnerable XML parser"""
    xml_data = request.get_data()
    if xml_data:
        # Vulnerable XML parser with XXE enabled
        import xml.etree.ElementTree as ET
        try:
            # Vulnerable: Parsing XML without disabling external entities
            root = ET.fromstring(xml_data)
            return f"Parsed XML root tag: {root.tag}"
        except:
            return "Invalid XML format"
    return "XML parser endpoint - POST XML data"

# Intentionally vulnerable: HTTP header injection (CKV3_SAST_88)
@app.route('/redirect')
def redirect_user():
    """Intentionally vulnerable redirect with header injection"""
    location = request.args.get('url', 'https://example.com')
    # Vulnerable: Direct header injection
    response = make_response("Redirecting...")
    response.headers['Location'] = location
    response.headers['Set-Cookie'] = f"redirect_url={location}; HttpOnly=False"  # CKV3_SAST_53
    return response, 302

# Intentionally vulnerable: NoSQL injection (CKV3_SAST_52)
@app.route('/mongo')
def mongo_query():
    """Intentionally vulnerable MongoDB query"""
    user_id = request.args.get('id', '')
    if user_id:
        # Vulnerable: Direct MongoDB query construction
        from pymongo import MongoClient
        query = f"{{'user_id': '{user_id}'}}"
        return f"MongoDB query: db.users.find({query})"
    return "MongoDB endpoint - provide ?id=userid"

# Intentionally vulnerable: JWT without verification (CKV3_SAST_54)
@app.route('/token')
def decode_token():
    """Intentionally vulnerable JWT decoder - TRULY EXPLOITABLE"""
    token = request.args.get('jwt', '')
    if token:
        # Vulnerable: JWT decoded without signature verification
        import jwt
        try:
            # TRULY EXPLOITABLE: Decode with options to skip verification
            payload = jwt.decode(token, options={"verify_signature": False}, algorithms=['HS256', 'none'])
            return f"JWT payload (decoded without verification): {payload}"
        except Exception as e:
            # Try base64 decode as fallback to demonstrate vulnerability
            try:
                import base64
                parts = token.split('.')
                if len(parts) >= 2:
                    # Pad the base64 string if needed
                    payload_b64 = parts[1]
                    padding = 4 - len(payload_b64) % 4
                    if padding != 4:
                        payload_b64 += '=' * padding
                    payload_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
                    return f"JWT payload (base64 decoded - no verification): {payload_json}"
            except:
                pass
            return f"Invalid JWT format: {e}"
    return "JWT endpoint - provide ?jwt=token"

# Intentionally vulnerable: Email sending (CKV3_SAST_63)
@app.route('/email')
def send_email():
    """Intentionally vulnerable email sending"""
    to_email = request.args.get('to', '')
    message = request.args.get('msg', 'Test message')
    if to_email:
        # Vulnerable: Unencrypted email configuration
        import smtplib
        server_config = {
            'host': 'smtp.example.com',
            'port': 25,  # Unencrypted port
            'use_tls': False,  # No encryption
            'username': 'admin',
            'password': 'password123'  # Hardcoded password
        }
        return f"Email sent to {to_email}: {message} via unencrypted SMTP"
    return "Email endpoint - provide ?to=email&msg=message"

# Intentionally vulnerable: Random values (CKV3_SAST_167)
@app.route('/random')
def generate_random():
    """Intentionally vulnerable random number generation"""
    import random
    # Vulnerable: Using weak random module
    random.seed(12345)  # Predictable seed
    token = random.randint(1000, 9999)
    session_id = random.random()
    return f"Random token: {token}, Session ID: {session_id}"

# Intentionally vulnerable: JSON injection (CKV3_SAST_82)
@app.route('/json')
def parse_json():
    """Intentionally vulnerable JSON parser"""
    json_str = request.args.get('data', '')
    if json_str:
        # Vulnerable: Using eval to parse JSON
        try:
            result = eval(f"dict({json_str})")  # Dangerous eval usage
            return f"JSON parsed: {result}"
        except Exception as e:
            return f"JSON error: {e}"
    return "JSON endpoint - provide ?data=key:value"

# Intentionally vulnerable: HTML autoescape disabled (CKV3_SAST_60)
@app.route('/template')
def render_unsafe_template():
    """Intentionally vulnerable template rendering"""
    user_input = request.args.get('input', '<script>alert("xss")</script>')
    # Vulnerable: Template with autoescape disabled
    try:
        from markupsafe import Markup
    except ImportError:
        from flask import Markup
    unsafe_html = Markup(user_input)  # Marks as safe, bypassing escaping
    return f"<h1>User Input:</h1><div>{unsafe_html}</div>"

# Intentionally vulnerable: Improper exception handling (CKV3_SAST_4)
@app.route('/exception')
def handle_exception():
    """Intentionally vulnerable exception handling"""
    try:
        # Intentionally cause various exceptions
        test_type = request.args.get('type', 'division')
        if test_type == 'division':
            result = 1 / 0  # Division by zero
        elif test_type == 'index':
            lst = [1, 2, 3]
            result = lst[10]  # Index error
        elif test_type == 'key':
            d = {'a': 1}
            result = d['nonexistent']  # Key error
    except:
        # Vulnerable: Broad exception handling without proper error information
        pass  # Silent failure - no proper error handling
    return "Exception handled (silently)"

# Intentionally vulnerable: None attribute access (CKV3_SAST_73)
@app.route('/none')
def access_none():
    """Intentionally vulnerable None attribute access"""
    data = None
    # Vulnerable: Accessing attributes on None without proper checks
    try:
        result = data.upper()  # Will cause AttributeError
        return f"Result: {result}"
    except AttributeError:
        return "AttributeError: accessing None attributes"

# Intentionally vulnerable: Wildcard usage (CKV3_SAST_170)
@app.route('/wildcard')
def wildcard_usage():
    """Intentionally vulnerable wildcard usage - TRULY EXPLOITABLE"""
    pattern = request.args.get('pattern', '*.txt')
    import glob
    # TRULY EXPLOITABLE: User-controlled wildcard pattern with NO prefix restriction
    # Attacker can enumerate entire filesystem with patterns like /etc/* or /*
    files = glob.glob(pattern)
    return f"Files matching pattern: {files}"

# Intentionally vulnerable: Improper access control (CKV3_SAST_97)
@app.route('/admin')
def admin_panel():
    """Intentionally vulnerable admin access"""
    # Vulnerable: No proper authorization check
    user_role = request.args.get('role', 'user')
    if user_role:  # Weak check - any non-empty role grants access
        return "Welcome to admin panel! Sensitive admin data here."
    return "Access denied"

# Intentionally vulnerable: Inadequate SSL/TLS (CKV3_SAST_65)
@app.route('/ssl_test')
def ssl_configuration():
    """Show intentionally weak SSL configuration"""
    import ssl
    # Vulnerable SSL context
    context = ssl.create_default_context()
    context.check_hostname = False  # Disable hostname verification
    context.verify_mode = ssl.CERT_NONE  # Disable certificate verification
    context.minimum_version = ssl.TLSVersion.SSLv3  # Use weak SSL version
    
    return "SSL context configured with weak security settings"

# Intentionally vulnerable: AES initialization vector (CKV3_SAST_68)
@app.route('/encrypt')
def encrypt_data():
    """Intentionally vulnerable encryption"""
    data = request.args.get('data', 'secret message')
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    import os
    
    # Vulnerable: Using weak IV
    key = b'1234567890123456'  # Weak key
    iv = b'1234567890123456'   # Static IV - should be random
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad data to block size
    padded_data = data.encode().ljust(16, b'\0')
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    
    return f"Encrypted with static IV: {encrypted.hex()}"

# Intentionally vulnerable: Key exchange without authentication (CKV3_SAST_98)
@app.route('/keyexchange')
def key_exchange():
    """Intentionally vulnerable key exchange"""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    
    # Vulnerable: Key exchange without proper authentication
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,  # Weak key size
        backend=default_backend()
    )
    
    public_key = private_key.public_key()
    return "Key exchange performed without entity authentication"

# Intentionally vulnerable: CSRF protections disabled (CKV3_SAST_56)
@app.route('/transfer', methods=['POST', 'GET'])
def csrf_vulnerable_transfer():
    """Intentionally vulnerable money transfer without CSRF protection"""
    if request.method == 'POST':
        # Vulnerable: No CSRF token validation
        amount = request.form.get('amount', '100')
        to_account = request.form.get('to_account', '12345')
        return f"Transfer of ${amount} to account {to_account} completed (no CSRF protection)"
    return '''
    <form method="POST">
        Amount: <input name="amount" value="100"><br>
        To Account: <input name="to_account" value="12345"><br>
        <input type="submit" value="Transfer">
    </form>
    '''

# Intentionally vulnerable: Cleartext transmission (CKV3_SAST_93)
@app.route('/credentials')
def cleartext_credentials():
    """Intentionally vulnerable cleartext credential transmission"""
    import base64
    # Vulnerable: Transmitting credentials in cleartext
    username = "admin"
    password = "password123"
    
    # Simulate cleartext transmission
    credentials = f"{username}:{password}"
    encoded_creds = base64.b64encode(credentials.encode()).decode()
    
    return f"Credentials transmitted in cleartext: {credentials} (Base64: {encoded_creds})"

# Intentionally vulnerable: Machine learning model download (CKV3_SAST_99)
@app.route('/ml_model')
def download_ml_model():
    """Intentionally vulnerable ML model download without integrity check"""
    # Testing endpoints for security scanning purposes only - these domains are fictitious
    test_malware_domains = ["malware.sigre.xyz", "hacker.sigre.xyz"]
    model_url = request.args.get('url', 'http://untrusted-source.com/model.pkl')
    
    # Check if URL contains test domains for security validation
    if any(domain in model_url for domain in test_malware_domains):
        return f"Test malware domain detected in URL: {model_url} - for security testing only"
    
    # Vulnerable: Downloading ML model without hash verification
    import requests
    try:
        response = requests.get(model_url, verify=False)
        # No integrity check performed
        return f"Downloaded ML model from {model_url} without hash verification"
    except:
        return f"Failed to download model from {model_url}"

# Intentionally vulnerable: PyTorch missing hash check (CKV3_SAST_194)
@app.route('/pytorch')
def pytorch_vulnerability():
    """Intentionally vulnerable PyTorch model loading without integrity check"""
    # Testing endpoints for security scanning purposes only - these domains are fictitious
    test_malware_domains = ["malware.sigre.xyz", "hacker.sigre.xyz"]
    model_url = request.args.get('url', '')
    model_path = request.args.get('path', '/tmp/model.pth')
    
    # If URL provided, download without verification (like /ml_model)
    if model_url:
        # Check if URL contains test domains for security validation
        if any(domain in model_url for domain in test_malware_domains):
            return f"Test malware domain detected in URL: {model_url} - PyTorch model download blocked for security testing"
        
        # Vulnerable: Downloading model without hash verification
        import requests as req
        try:
            response = req.get(model_url, verify=False, timeout=5)
            # No integrity check performed - dangerous pickle deserialization
            return f"Downloaded PyTorch model from {model_url} without hash verification (size: {len(response.content)} bytes)"
        except Exception as e:
            return f"Failed to download PyTorch model from {model_url}: {e}"
    
    # Vulnerable: Loading local PyTorch model without hash check
    return f"PyTorch model loaded from {model_path} without hash verification"

# Intentionally vulnerable: Redis without SSL (CKV3_SAST_187)
@app.route('/redis')
def redis_no_ssl():
    """Intentionally vulnerable Redis connection without SSL"""
    # Vulnerable: Redis connection without SSL
    redis_config = {
        'host': 'localhost',
        'port': 6379,
        'ssl': False,  # No SSL encryption
        'password': None  # No authentication
    }
    return f"Redis configured without SSL: {redis_config}"

# Intentionally vulnerable: Improper limitation of pathname (CKV3_SAST_169)
@app.route('/download')
def download_file():
    """Intentionally vulnerable file download - TRULY EXPLOITABLE path traversal"""
    filename = request.args.get('file', 'data.txt')
    # TRULY EXPLOITABLE: Direct path traversal - no validation at all
    # Attacker can read any file with patterns like /etc/passwd or ../../../etc/passwd
    file_path = filename if filename.startswith('/') else f"./{filename}"
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        return f"File content from {file_path}:\n{content[:4000]}"
    except Exception as e:
        return f"Could not read file: {file_path} - {e}"

# Intentionally vulnerable: Lack of HTML tag neutralisation (CKV3_SAST_175)
@app.route('/html')
def html_tags():
    """Intentionally vulnerable HTML tag handling"""
    user_html = request.args.get('html', '<script>alert("xss")</script>')
    # Vulnerable: No HTML tag sanitisation
    return f"<div>User HTML: {user_html}</div>"

# Intentionally vulnerable: Uncontrolled resource consumption (CKV3_SAST_91)
@app.route('/resource')
def resource_consumption():
    """Intentionally vulnerable resource consumption"""
    size = int(request.args.get('size', '1000'))
    # Vulnerable: No limits on resource consumption
    data = 'x' * size * 1000000  # Can consume massive memory
    return f"Generated data of size: {len(data)} bytes"

# Intentionally vulnerable: Key exchange without entity authentication (CKV3_SAST_98)
@app.route('/dh_exchange')
def diffie_hellman():
    """Intentionally vulnerable Diffie-Hellman key exchange"""
    # Vulnerable: No entity authentication in key exchange
    from cryptography.hazmat.primitives.asymmetric import dh
    from cryptography.hazmat.backends import default_backend
    
    # Generate parameters (simplified)
    parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    
    return "Diffie-Hellman key exchange without entity authentication completed"

# Intentionally vulnerable: Improper control of configuration inputs (CKV3_SAST_168)
@app.route('/config')
def config_injection():
    """Intentionally vulnerable configuration input handling - TRULY EXPLOITABLE"""
    config_param = request.args.get('config', 'debug=true')
    # Vulnerable: Direct configuration parameter execution
    try:
        # TRULY EXPLOITABLE: Dangerous exec() with code injection
        key = config_param.split('=')[0]
        value_expr = config_param.split('=')[1]
        exec(f"app.config['{key}'] = {value_expr}")
        # Return computed value as PROOF of code execution
        computed_value = app.config.get(key)
        return f"Configuration updated: {key} = {computed_value} (computed from: {value_expr})"
    except Exception as e:
        return f"Configuration error with: {config_param} - {e}"

# Intentionally vulnerable: Improper authorisation in custom URL scheme (CKV3_SAST_70)
@app.route('/custom_scheme')
def custom_url_scheme():
    """Intentionally vulnerable custom URL scheme handler"""
    url_scheme = request.args.get('scheme', 'myapp://admin/data')
    # Vulnerable: No proper authorisation for custom schemes
    if url_scheme.startswith('myapp://'):
        # Improper authorisation - anyone can access admin functions
        return f"Handling custom URL scheme: {url_scheme} without proper authorisation"
    return "Invalid scheme"

# Intentionally vulnerable: LDAP anonymous binds (CKV3_SAST_66)
@app.route('/ldap_anon')
def ldap_anonymous():
    """Intentionally vulnerable LDAP anonymous binding"""
    # Vulnerable: LDAP anonymous bind configuration
    ldap_config = {
        'server': 'ldap://localhost:389',
        'bind_dn': None,  # Anonymous bind
        'bind_password': None,
        'anonymous': True
    }
    return f"LDAP configured with anonymous bind: {ldap_config}"

# Intentionally vulnerable: Use of insecure IPMI modules (CKV3_SAST_37)
@app.route('/ipmi')
def ipmi_insecure():
    """Intentionally vulnerable IPMI configuration"""
    # Vulnerable: Insecure IPMI settings
    ipmi_config = {
        'default_username': 'admin',
        'default_password': 'admin',
        'encryption': False,
        'authentication': 'none',
        'privilege_level': 'administrator'
    }
    return f"IPMI configured insecurely: {ipmi_config}"

# Intentionally vulnerable: Files assigned loose permissions (CKV3_SAST_69)
@app.route('/permissions')
def file_permissions():
    """Intentionally vulnerable file permission assignment"""
    filename = request.args.get('file', 'test.txt')
    content = request.args.get('content', 'sensitive data')
    
    import os
    import stat
    
    # Vulnerable: Creating file with overly permissive permissions
    file_path = f"/tmp/{filename}"
    with open(file_path, 'w') as f:
        f.write(content)
    
    # Set dangerous permissions: read/write/execute for everyone
    os.chmod(file_path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)  # 777
    
    return f"File {file_path} created with 777 permissions (world-readable/writable)"

# Intentionally vulnerable: TensorFlow model security (CKV3_SAST_194)
@app.route('/tensorflow')
def tensorflow_model():
    """Intentionally vulnerable TensorFlow model loading without integrity check"""
    # Testing endpoints for security scanning purposes only - these domains are fictitious
    test_malware_domains = ["malware.sigre.xyz", "hacker.sigre.xyz"]
    model_url = request.args.get('url', '')
    model_path = request.args.get('model', 'model.h5')
    
    # If URL provided, download without verification (like /ml_model)
    if model_url:
        # Check if URL contains test domains for security validation
        if any(domain in model_url for domain in test_malware_domains):
            return f"Test malware domain detected in URL: {model_url} - TensorFlow model download blocked for security testing"
        
        # Vulnerable: Downloading model without hash verification
        import requests as req
        try:
            response = req.get(model_url, verify=False, timeout=5)
            # No integrity check performed - could contain malicious ops
            return f"Downloaded TensorFlow model from {model_url} without hash verification (size: {len(response.content)} bytes)"
        except Exception as e:
            return f"Failed to download TensorFlow model from {model_url}: {e}"
    
    # Vulnerable: Loading local model without integrity verification
    return f"TensorFlow model {model_path} loaded without integrity verification"

# Intentionally vulnerable: Resource exhaustion (CKV3_SAST_91)
@app.route('/exhaust')
def resource_exhaustion():
    """Intentionally vulnerable resource exhaustion"""
    size = request.args.get('size', '1000')
    try:
        # Vulnerable: Uncontrolled memory allocation
        size_int = int(size)
        if size_int > 100000:  # Limit to prevent actual crashes in demo
            size_int = 100000
        # Simulate memory exhaustion vulnerability
        data = 'x' * size_int
        return f"Memory allocated: {len(data)} bytes (resource exhaustion vulnerability)"
    except (ValueError, MemoryError) as e:
        return f"Resource exhaustion attempt failed: {str(e)}"

# Intentionally vulnerable: XML External Entity (CKV3_SAST_50, CKV3_SAST_90)
@app.route('/xml')
def xml_parser():
    """Intentionally vulnerable XML parser"""
    xml_data = request.args.get('data', '')
    if xml_data:
        try:
            # Vulnerable: XML parser with external entities enabled
            import xml.etree.ElementTree as ET
            # Parse XML without disabling external entities (vulnerable)
            root = ET.fromstring(xml_data)
            return f"XML parsed successfully: {root.tag} - {root.text}"
        except ET.ParseError as e:
            return f"XML parsing error: {str(e)}"
        except Exception as e:
            return f"XML processing error: {str(e)}"
    return "XML endpoint - provide ?data=<xml>content</xml>"

# Intentionally vulnerable: Weak Database Authentication (CKV3_SAST_71)
@app.route('/database')
def database_config():
    """Intentionally vulnerable database configuration with SQL injection"""
    operation = request.args.get('op', 'config')
    query = request.args.get('query', '')
    
    if operation == 'config':
        # Vulnerable: Hardcoded database credentials
        db_config = {
            'host': 'localhost',
            'port': 5432,
            'username': 'admin',
            'password': 'password123',
            'database': 'bankdata',
            'ssl_mode': 'disable',
            'authentication': 'plaintext'
        }
        return f"Database configuration: {db_config}"
    elif operation == 'connect':
        # Vulnerable: Connection string with credentials
        conn_string = "postgresql://admin:password123@localhost:5432/bankdata?sslmode=disable"
        return f"Database connection string: {conn_string}"
    elif operation == 'query' and query:
        # Vulnerable: Direct SQL execution without sanitisation (SQL injection)
        import sqlite3
        try:
            # Use in-memory database for demo to avoid affecting real data
            conn = sqlite3.connect(':memory:')
            cursor = conn.cursor()
            # Create demo table
            cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER, username TEXT, password TEXT)")
            cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'password123')")
            cursor.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'secret456')")
            conn.commit()
            # Vulnerable: Execute user-provided query directly
            cursor.execute(query)  # SQL INJECTION VULNERABILITY
            results = cursor.fetchall()
            conn.close()
            return f"Query executed: {query}\nResults: {results}"
        except Exception as e:
            return f"SQL error: {e}\nQuery was: {query}"
    else:
        return f"Database operation '{operation}' executed with hardcoded credentials. Use ?op=query&query=SELECT * FROM users for SQL injection demo."

with app.app_context():
    import models
    try:
        db.create_all()
    except Exception as e:
        # For Docker deployment: create database directory if it doesn't exist
        import os
        db_url = app.config.get('SQLALCHEMY_DATABASE_URI', '')
        if 'sqlite:///' in db_url:
            db_path = db_url.replace('sqlite:///', '')
            db_dir = os.path.dirname(db_path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
                os.chmod(db_dir, 0o777)  # Vulnerable permissions for testing
        # Retry database creation
        try:
            db.create_all()
        except Exception as retry_error:
            print(f"Database creation failed: {retry_error}")
            # Continue anyway for testing purposes

# Lab applications removed - vulnerabilities built into main app

# Start background auth traffic generator for SIEM testing
start_auth_generator()
