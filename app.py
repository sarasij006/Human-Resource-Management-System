import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from threading import Thread

from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

from config import config_mapping

# ---------------------------------------------------------------------------
# 1. APP SETUP & EXTENSION INITIALIZATION
# ---------------------------------------------------------------------------

# Instantiate core extensions
db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()
migrate = Migrate()
csrf = CSRFProtect()

def create_app():
    """Initializes and configures the centralized application instance."""
    app = Flask(__name__)
    
    # Determine execution runtime target
    env_target = os.environ.get('FLASK_ENV', 'development')
    app.config.from_object(config_mapping[env_target])
    
    # Bind extensions to runtime state
    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    
    # Authentication access boundaries configuration
    login_manager.login_view = 'login'  # type: ignore
    login_manager.login_message_category = 'warning'
    login_manager.login_message = 'Please sign in to access this secure resource.'
    
    return app

# Instantiate the singular running app instance for the system execution boundary
app = create_app()

@app.route('/healthz')
def health_check():
    """System heartbeat endpoint."""
    return jsonify({
        "status": "operational", 
        "database": "connected" if db.engine else "offline"
    }), 200

# ---------------------------------------------------------------------------
# 2. DATABASE MODELS
# ---------------------------------------------------------------------------
class User(db.Model, UserMixin):
    """
    Production-grade User entity mapping system authentication and identity profiles.
    Compatible with both SQLite development and PostgreSQL production layers.
    """
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    
    # Core Corporate Identifiers (Unique, Index-optimized)
    employee_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    
    # Cryptographic Perimeter Security
    password_hash = db.Column(db.String(255), nullable=False)
    
    # Role Enforcement Perimeter ('HR' or 'Employee')
    role = db.Column(db.String(20), nullable=False, default='Employee')
    
    # Authentication & Email Verification Flow Properties
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    verification_token = db.Column(db.String(100), unique=True, nullable=True)
    token_expires_at = db.Column(db.DateTime, nullable=True)
    
    # Audit Trail Lifecycles
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now(), onupdate=db.func.now())

    @property
    def password(self):
        """Prevents direct plain-text reading of the password property."""
        raise AttributeError('Password is not a readable system attribute.')

    @password.setter
    def password(self, plain_text_password):
        """Intercepts, hashes, and secures plain-text credentials."""
        self.password_hash = generate_password_hash(plain_text_password)

    def verify_password(self, plain_text_password):
        """
        Safely evaluates plain-text passwords against the stored cryptographic hash.
        Protects against timing attacks.
        """
        return check_password_hash(self.password_hash, plain_text_password)

    def is_token_valid(self):
        """Evaluates whether the active verification token is within its valid operational lifespan."""
        if not self.token_expires_at:
            return False
        # Ensure the expiry check is timezone-naive matching SQLite/PostgreSQL default configurations
        return datetime.now(timezone.utc).replace(tzinfo=None) < self.token_expires_at

    def __repr__(self):
        return f"<User {self.employee_id} - Role: {self.role}>"


@login_manager.user_loader
def load_user(user_id):
    """
    Flask-Login callback hook. 
    Retrieves the User record from the persistent layer during session parsing.
    """
    return User.query.get(int(user_id))

# ---------------------------------------------------------------------------
# 3. FORMS & VALIDATION LAYER
# ---------------------------------------------------------------------------

def check_password_complexity(password):
    """Enforces enterprise password requirements server-side."""
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[^A-Za-z0-9]", password):
        return False
    return True

def generate_secure_token():
    """Generates a high-entropy cryptographically secure string token."""
    return secrets.token_urlsafe(32)

def role_required(target_role):
    """Secures access boundaries to users with designated role profiles."""
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if current_user.role != target_role:
                abort(403) # Secure Forbidden Response
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ---------------------------------------------------------------------------
# 4. ASYNCHRONOUS TRANSACTIONAL EMAIL ENGINE
# ---------------------------------------------------------------------------

def send_background_email(app_instance, message):
    """Worker routine running inside an independent thread context."""
    with app_instance.app_context():
        try:
            mail.send(message)
        except Exception as e:
            app_instance.logger.error(f"Asynchronous transactional email dispatch aborted: {str(e)}")

def dispatch_transactional_email(recipient_email, email_subject, template_source, **context_arguments):
    """
    Compiles and assigns HTML template components to an outbound background thread.
    Protects the main request loop from network I/O blockages.
    """
    current_app_obj = app
    html_payload = render_template(template_source, **context_arguments)
    
    message = Message(
        subject=email_subject,
        recipients=[recipient_email],
        html=html_payload
    )
    
    worker_thread = Thread(target=send_background_email, args=(current_app_obj, message))
    worker_thread.start()
    return worker_thread

# ---------------------------------------------------------------------------
# 5. ENDPOINTS & APPLICATION SYSTEM CONTROLLERS (ROUTES)
# ---------------------------------------------------------------------------

@app.route('/')
def landing():
    """Renders the centralized entry-point landing interface."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles secure new account creation operations."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        employee_id = request.form.get('employee_id', '').strip()
        role = request.form.get('role', 'Employee').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not employee_id or not email or not password:
            flash("All authorization matrix fields are required.", "danger")
            return render_template('register.html')
            
        if password != confirm_password:
            flash("Credential verification mismatch. Inputs must align.", "danger")
            return render_template('register.html')
            
        if not check_password_complexity(password):
            flash("Password fails security complexity constraints.", "danger")
            return render_template('register.html')
            
        if role not in ['Employee', 'HR']:
            flash("Malicious role parameter mutation detected.", "danger")
            return render_template('register.html')

        if User.query.filter_by(employee_id=employee_id).first():
            flash("Identifier conflict. Target entity already initialized.", "danger")
            return render_template('register.html')
            
        if User.query.filter_by(email=email).first():
            flash("Identity registration conflict. Email vector mapping exists.", "danger")
            return render_template('register.html')

        new_user = User(
            employee_id=employee_id,  # type: ignore
            email=email,  # type: ignore
            role=role,  # type: ignore
            password=password,  # type: ignore
            email_verified=False,  # type: ignore
            verification_token=generate_secure_token(),  # type: ignore
            token_expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(seconds=app.config['TOKEN_EXPIRATION_SECONDS'])  # type: ignore
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            
            dispatch_transactional_email(
                recipient_email=new_user.email,
                email_subject="Action Required: Verify Identity Parameter Ledger",
                template_source="email_verify.html",
                token=new_user.verification_token
            )
            
            return redirect(url_for('verify_pending', email=email))
        except Exception as e:
            db.session.rollback()
            flash("Persistent storage write failure. Contact architecture desk.", "danger")
            return render_template('register.html')

    return render_template('register.html')


@app.route('/verify-pending')
def verify_pending():
    """Intercepts post-registration flows until confirmation occurs."""
    email = request.args.get('email', '')
    return render_template('verify_pending.html', email=email)


@app.route('/verify-email/<token>')
def verify_email(token):
    """Processes cryptographic email confirmation transaction sequences."""
    user = User.query.filter_by(verification_token=token).first()
    
    if not user or not user.is_token_valid():
        return render_template('verify_email.html', success=False)
        
    user.email_verified = True
    user.verification_token = None
    user.token_expires_at = None
    db.session.commit()
    
    return render_template('verify_email.html', success=True)


@app.route('/resend-verification', methods=['POST'])
def resend_verification():
    """Refreshes and routes a clean activation link vector."""
    email = request.form.get('email', '').strip().lower()
    user = User.query.filter_by(email=email, email_verified=False).first()
    
    if user:
        user.verification_token = generate_secure_token()
        user.token_expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(seconds=app.config['TOKEN_EXPIRATION_SECONDS'])
        db.session.commit()
        
        dispatch_transactional_email(
            recipient_email=user.email,
            email_subject="Action Required: Verification Token Refreshed",
            template_source="email_verify.html",
            token=user.verification_token
        )
        flash("A new cryptographic token handshake has been routed.", "success")
    else:
        flash("If user registration exists, verification token refreshed successfully.", "success")
        
    return redirect(url_for('verify_pending', email=email))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Executes stateful user workspace session mapping operations."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = True if request.form.get('remember') else False
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.verify_password(password):
            if not user.email_verified:
                flash("Ecosystem entry blocked. Unverified parameter profile. Confirm via inbox link.", "warning")
                return redirect(url_for('verify_pending', email=email))
                
            login_user(user, remember=remember)
            return redirect(url_for('dashboard'))
        
        flash("Invalid identification credentials or unverified account parameter bounds.", "danger")

    return render_template('login.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Triggers secure access recovery payload configurations."""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user = User.query.filter_by(email=email).first()
        
        if user:
            user.verification_token = generate_secure_token()
            user.token_expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(seconds=app.config['TOKEN_EXPIRATION_SECONDS'])
            db.session.commit()
            
            dispatch_transactional_email(
                recipient_email=user.email,
                email_subject="Security Protocol: Credential Overwrite Token Request",
                template_source="email_reset.html",
                token=user.verification_token
            )
            
        flash("If matching corporate criteria is met, a reset payload link has been issued.", "success")
        
    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Executes a permanent password overwrite matrix operation."""
    user = User.query.filter_by(verification_token=token).first()
    
    if not user or not user.is_token_valid():
        flash("Authorization recovery handshake matrix is invalid or expired.", "danger")
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if password != confirm_password:
            flash("Credential verification mismatch.", "danger")
            return render_template('reset_password.html', token=token)
            
        if not check_password_complexity(password):
            flash("Password fails structural complexity constraint metrics.", "danger")
            return render_template('reset_password.html', token=token)
            
        user.password = password
        user.verification_token = None
        user.token_expires_at = None
        db.session.commit()
        
        flash("Cryptographic credential matrix patched. Authenticate with new parameters.", "success")
        return redirect(url_for('login'))
        
    return render_template('reset_password.html', token=token)


@app.route('/dashboard')
@login_required
def dashboard():
    """Renders the single role-branching control system dashboard interface."""
    return render_template('dashboard.html')


@app.route('/logout')
@login_required
def logout():
    """Destroys structural user browser cookies and terminates active session maps."""
    logout_user()
    flash("Session context systematically torn down. Device connection disconnected.", "success")
    return redirect(url_for('login'))

# HTTP Error Handlers for Production Compliance
@app.errorhandler(403)
def forbidden_boundary(e):
    return render_template('base.html', content="<div class='glass-card p-5 text-center text-danger'><i class='fa-solid fa-ban fs-1 mb-3'></i><h3>Access Denied</h3><p class='small text-muted'>Your node clearance scope does not match this system block destination boundary.</p></div>"), 403

@app.errorhandler(404)
def resource_not_found_boundary(e):
    return render_template('base.html', content="<div class='glass-card p-5 text-center text-warning'><i class='fa-solid fa-compass fs-1 mb-3'></i><h3>Cluster Coordinate Missing</h3><p class='small text-muted'>The requested coordinate node address does not map inside this system.</p></div>"), 404

# ---------------------------------------------------------------------------
# 6. AUTOMATIC DATABASE SCHEMA INITIALIZATION (HACKATHON LIFECYCLE HOOK)
# ---------------------------------------------------------------------------

_database_initialized = False

@app.before_request
def bootstrap_database_schema():
    """
    Automatically builds database tables on the initial application request thread.
    Eliminates manual CLI setup friction during hackathon evaluation.
    """
    global _database_initialized
    if not _database_initialized:
        try:
            db.create_all()
            _database_initialized = True
        except Exception as e:
            app.logger.error(f"Critical schema initialization failure: {str(e)}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))