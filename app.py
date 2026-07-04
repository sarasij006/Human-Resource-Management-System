import os
import re
import sqlite3
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
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
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


@event.listens_for(Engine, "connect")
def configure_sqlite_runtime(dbapi_connection, connection_record):
    """Applies safer SQLite pragmas for this local HRMS runtime."""
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=MEMORY")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()

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
# ---------------------------------------------------------------------------
# 2. DATABASE MODELS (EXPANDED FOR HRMS)
# ---------------------------------------------------------------------------
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='Employee')
    
    # Profile Details (Linked to profile.html)
    job_title = db.Column(db.String(100), default='Unassigned')
    salary_structure = db.Column(db.String(255), default='Pending HR Allocation')
    address = db.Column(db.Text, nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    profile_picture = db.Column(db.String(255), nullable=True, default=None)
    
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    verification_token = db.Column(db.String(100), unique=True, nullable=True)
    token_expires_at = db.Column(db.DateTime, nullable=True)

    @property
    def password(self):
        raise AttributeError('Password is not readable.')

    @password.setter
    def password(self, plain_text_password):
        self.password_hash = generate_password_hash(plain_text_password)

    def verify_password(self, plain_text_password):
        return check_password_hash(self.password_hash, plain_text_password)

    def is_token_valid(self):
        if not self.token_expires_at:
            return False
        return datetime.now(timezone.utc).replace(tzinfo=None) < self.token_expires_at

class Attendance(db.Model):
    """Tracks employee clock-in and clock-out cycles (Linked to attendance.html)"""
    __tablename__ = 'attendance'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    date = db.Column(db.Date, default=lambda: datetime.now(timezone.utc).date())
    check_in = db.Column(db.DateTime, nullable=True)
    check_out = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default='Present')
    user = db.relationship('User', backref=db.backref('attendance_records', lazy=True))


class LeaveRequest(db.Model):
    """Tracks time-off requests (Linked to leaves.html & hr_dashboard.html)"""
    __tablename__ = 'leave_requests'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    leave_type = db.Column(db.String(50), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    remarks = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Pending') # Pending, Approved, Rejected, Resolved
    hr_comments = db.Column(db.Text, nullable=True) # NEW: Stores HR feedback
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    
    # Establish a relationship back to the User model so we can pull employee emails/IDs easily
    user = db.relationship('User', backref=db.backref('leave_requests', lazy=True))

@login_manager.user_loader
def load_user(user_id):
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


def iter_dates(start_date, end_date):
    """Yields each date across an inclusive range."""
    current_date = start_date
    while current_date <= end_date:
        yield current_date
        current_date += timedelta(days=1)


def parse_leave_dates(form_payload):
    """Accepts either hidden start/end fields or a flatpickr date-range string."""
    start_str = form_payload.get('start_date', '').strip()
    end_str = form_payload.get('end_date', '').strip()
    range_str = form_payload.get('date_range', '').strip()

    if range_str and (not start_str or not end_str):
        if ' to ' in range_str:
            start_str, end_str = [item.strip() for item in range_str.split(' to ', 1)]
        else:
            start_str = range_str
            end_str = range_str

    if not start_str or not end_str:
        raise ValueError("Missing leave dates.")

    start_date = datetime.strptime(start_str, '%Y-%m-%d').date()
    end_date = datetime.strptime(end_str, '%Y-%m-%d').date()
    return start_date, end_date


def find_attendance_conflicts(user_id, start_date, end_date):
    """Returns attendance rows that would conflict with approving or applying leave."""
    return Attendance.query.filter(
        Attendance.user_id == user_id,
        Attendance.date >= start_date,
        Attendance.date <= end_date,
        Attendance.status.in_(['Present', 'Half Day'])
    ).all()


def sync_leave_attendance_records(leave_request):
    """
    Mirrors approved leave into attendance so both employee and HR dashboards
    read the same daily status history.
    """
    should_create_leave_records = leave_request.status == 'Approved'

    for target_date in iter_dates(leave_request.start_date, leave_request.end_date):
        record = Attendance.query.filter_by(
            user_id=leave_request.user_id,
            date=target_date
        ).first()

        if should_create_leave_records:
            if record is None:
                db.session.add(Attendance(
                    user_id=leave_request.user_id,  # type: ignore
                    date=target_date,  # type: ignore
                    check_in=None,  # type: ignore
                    check_out=None,  # type: ignore
                    status='Leave'  # type: ignore
                ))
            elif record.status == 'Leave' and not record.check_in and not record.check_out:
                record.status = 'Leave'
        elif record and record.status == 'Leave' and not record.check_in and not record.check_out:
            db.session.delete(record)


def build_employee_calendar_events(user_id):
    """Builds combined attendance and leave calendar events for the employee view."""
    attendance_rows = Attendance.query.filter_by(user_id=user_id).order_by(Attendance.date.asc()).all()
    leave_rows = LeaveRequest.query.filter_by(user_id=user_id).order_by(LeaveRequest.created_at.desc()).all()

    events = []
    attendance_dates = set()
    approved_leave_dates = set()
    timeline_dates = []

    attendance_colors = {
        'Present': '#10B981',
        'Half Day': '#F59E0B',
        'Absent': '#EF4444',
        'Leave': '#3B82F6'
    }

    for record in attendance_rows:
        attendance_dates.add(record.date)
        timeline_dates.append(record.date)

        if record.status == 'Leave':
            continue

        events.append({
            "title": record.status,
            "start": record.date.strftime("%Y-%m-%d"),
            "color": attendance_colors.get(record.status, '#6C757D'),
            "allDay": True
        })

    leave_colors = {
        'Approved': '#2563EB',
        'Pending': '#FBBF24',
        'Rejected': '#EF4444'
    }

    for leave in leave_rows:
        timeline_dates.append(leave.start_date)

        if leave.status == 'Approved':
            for target_date in iter_dates(leave.start_date, leave.end_date):
                approved_leave_dates.add(target_date)

        events.append({
            "title": f"{leave.leave_type} Leave ({leave.status})",
            "start": leave.start_date.strftime("%Y-%m-%d"),
            "end": (leave.end_date + timedelta(days=1)).strftime("%Y-%m-%d"),
            "color": leave_colors.get(leave.status, '#6C757D'),
            "allDay": True
        })

    if timeline_dates:
        first_date = min(timeline_dates)
        today = datetime.now(timezone.utc).date()
        for target_date in iter_dates(first_date, today):
            if target_date.weekday() >= 5:
                continue
            if target_date in attendance_dates or target_date in approved_leave_dates:
                continue

            events.append({
                "title": "Absent",
                "start": target_date.strftime("%Y-%m-%d"),
                "color": attendance_colors['Absent'],
                "allDay": True
            })

    return events

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
        if current_user.role == 'HR':
            return redirect(url_for('hr_dashboard'))
        return redirect(url_for('dashboard'))
    return render_template('landing.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles secure new account creation operations and waits for verification."""
    if current_user.is_authenticated:
        if current_user.role == 'HR':
            return redirect(url_for('hr_dashboard'))
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        employee_id = request.form.get('employee_id', '').strip()
        role = request.form.get('role', 'Employee').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not employee_id or not email or not password:
            flash("All required registration fields must be completed.", "danger")
            return render_template('register.html')

        if password != confirm_password:
            flash("Password and confirm password must match.", "danger")
            return render_template('register.html')

        if not check_password_complexity(password):
            flash("Password must include uppercase, lowercase, number, and special character.", "danger")
            return render_template('register.html')

        if role not in ['Employee', 'HR']:
            flash("Invalid role selection.", "danger")
            return render_template('register.html')

        if User.query.filter_by(employee_id=employee_id).first():
            flash("This employee ID is already registered.", "danger")
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash("This email is already registered.", "danger")
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
            
            # SUCCESS: Redirect to verification page instead of logging in
            return redirect(url_for('verify_pending', email=email))
                
        except Exception:
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
        if current_user.role == 'HR':
            return redirect(url_for('hr_dashboard'))
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = True if request.form.get('remember') else False
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.verify_password(password):
            # Check if email is verified first
            if not user.email_verified:
                flash("Ecosystem entry blocked. Unverified parameter profile. Confirm via inbox link.", "warning")
                return redirect(url_for('verify_pending', email=email))
                
            # Log them in
            login_user(user, remember=remember)
            
            # Check role and redirect
            if user.role == 'HR':
                return redirect(url_for('hr_dashboard'))
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
    """Renders dashboard.html with real-time employee data."""
    if current_user.role == 'HR':
        return redirect(url_for('hr_dashboard'))

    # Fetch recent activity for the bottom grid
    recent_attendance = Attendance.query.filter_by(user_id=current_user.id).order_by(Attendance.check_in.desc()).limit(3).all()
    recent_leaves = LeaveRequest.query.filter_by(user_id=current_user.id).order_by(LeaveRequest.created_at.desc()).limit(4).all()
    
    return render_template('dashboard.html', 
                           attendance=recent_attendance, 
                           leaves=recent_leaves)


@app.route('/payroll')
@login_required
def payroll():
    """Renders a read-only payroll view for employees."""
    if current_user.role == 'HR':
        return redirect(url_for('hr_dashboard'))

    return render_template('payroll.html', user=current_user)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """Renders profile.html and handles contact info & picture updates."""
    if request.method == 'POST':
        # 1. Update text fields
        current_user.address = request.form.get('address', current_user.address)
        current_user.phone = request.form.get('phone', current_user.phone)
        
        # 2. Handle Profile Picture Upload
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and file.filename and file.filename != '':
                # Clean the filename to prevent directory traversal attacks
                filename = secure_filename(file.filename)
                
                # Append user ID to make the filename unique (e.g., user_1_photo.jpg)
                ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'jpg'
                new_filename = f"user_{current_user.id}_avatar.{ext}"
                
                # Ensure the upload directory exists
                upload_folder = os.path.join(app.root_path, 'static', 'profile_pics')
                os.makedirs(upload_folder, exist_ok=True)
                
                # Save the physical file and update the database record
                file.save(os.path.join(upload_folder, new_filename))
                current_user.profile_picture = new_filename

        db.session.commit()
        flash("Profile parameters updated successfully.", "success")
        return redirect(url_for('profile'))
        
    return render_template('profile.html', user=current_user)

@app.route('/attendance', methods=['GET', 'POST'])
@login_required
def attendance():
    """Renders attendance.html and handles daily clock cycles."""
    if current_user.role == 'HR':
        return redirect(url_for('hr_dashboard'))

    today = datetime.now(timezone.utc).date()
    record = Attendance.query.filter_by(user_id=current_user.id, date=today).first()
    approved_leave_today = LeaveRequest.query.filter(
        LeaveRequest.user_id == current_user.id,
        LeaveRequest.status == 'Approved',
        LeaveRequest.start_date <= today,
        LeaveRequest.end_date >= today
    ).first()
    
    if request.method == 'POST':
        action = request.form.get('action')

        if approved_leave_today:
            flash("You already have approved leave for today. Please contact HR to adjust it before checking in.", "warning")
            return redirect(url_for('attendance'))

        if action == 'check_in' and not record:
            current_timestamp = datetime.now(timezone.utc).replace(tzinfo=None)
            new_record = Attendance(
                user_id=current_user.id,  # type: ignore
                date=today,  # type: ignore
                check_in=current_timestamp,  # type: ignore
                status='Present'  # type: ignore
            )
            db.session.add(new_record)
            db.session.commit()
            flash("Checked in successfully.", "success")
            
        elif action == 'check_out' and record and not record.check_out:
            record.check_out = datetime.now(timezone.utc).replace(tzinfo=None)
            
            # Calculate hours worked for Half Day logic
            time_diff = record.check_out - record.check_in
            hours_worked = time_diff.total_seconds() / 3600
            if hours_worked < 4.0:
                record.status = 'Half Day'
                
            db.session.commit()
            flash("Checked out successfully.", "success")
            
        return redirect(url_for('attendance'))
        
    # Fetch all history for the logged-in employee (Employee-only view enforced here)
    history = Attendance.query.filter_by(user_id=current_user.id).order_by(Attendance.date.desc()).all()
    
    # Determine UI states for the buttons
    is_leave_record = record.status == 'Leave' if record else False
    is_checked_in = record is not None and not is_leave_record
    is_checked_out = record.check_out is not None if record else is_leave_record

    return render_template('attendance.html', 
                           history=history,
                           is_checked_in=is_checked_in,
                           is_checked_out=is_checked_out,
                           approved_leave_today=approved_leave_today)


@app.route('/leave-requests', methods=['GET', 'POST'])
@login_required
def leave_requests():
    """Renders leave requests and handles leave request submissions."""
    if current_user.role == 'HR':
        return redirect(url_for('hr_dashboard'))

    if request.method == 'POST':
        leave_type = request.form.get('leave_type', 'Paid').strip()
        remarks = request.form.get('remarks', '').strip()

        if leave_type not in ['Paid', 'Sick', 'Unpaid']:
            flash("Please choose a valid leave type.", "danger")
            return redirect(url_for('leave_requests'))

        if not remarks:
            flash("Remarks are required for every leave request.", "danger")
            return redirect(url_for('leave_requests'))

        try:
            start, end = parse_leave_dates(request.form)
        except ValueError:
            flash("Please choose a valid leave date range.", "danger")
            return redirect(url_for('leave_requests'))

        if start > end:
            flash("Start date cannot be after end date.", "danger")
            return redirect(url_for('leave_requests'))

        overlapping_request = LeaveRequest.query.filter(
            LeaveRequest.user_id == current_user.id,
            LeaveRequest.start_date <= end,
            LeaveRequest.end_date >= start,
            LeaveRequest.status.in_(['Pending', 'Approved'])
        ).first()

        if overlapping_request:
            flash("You already have a pending or approved leave request in that date range.", "danger")
            return redirect(url_for('leave_requests'))

        conflicts = find_attendance_conflicts(current_user.id, start, end)
        if conflicts:
            flash("Leave cannot be applied on dates that already have present or half-day attendance.", "danger")
            return redirect(url_for('leave_requests'))

        new_leave = LeaveRequest(
            user_id=current_user.id,  # type: ignore
            leave_type=leave_type,  # type: ignore
            start_date=start,  # type: ignore
            end_date=end,  # type: ignore
            remarks=remarks  # type: ignore
        )
        db.session.add(new_leave)
        db.session.commit()
        flash("Leave request submitted for HR approval.", "success")
            
        return redirect(url_for('leave_requests'))
        
    # Fetch pending leave requests for the logged-in employee
    pending_leaves = LeaveRequest.query.filter_by(user_id=current_user.id, status='Pending').order_by(LeaveRequest.created_at.desc()).all()
    all_leaves = LeaveRequest.query.filter_by(user_id=current_user.id).order_by(LeaveRequest.created_at.desc()).all()
    
    return render_template('leaves.html', pending_leaves=pending_leaves, all_leaves=all_leaves)


@app.route('/api/attendance-events', methods=['GET'])
@login_required
def api_get_attendance_events():
    """JSON Endpoint feeding dynamically styled data to FullCalendar"""
    if current_user.role == 'HR':
        abort(403)

    return jsonify(build_employee_calendar_events(current_user.id))


# ---------------------------------------------------------------------------
# HR ADMINISTRATION ROUTES
# ---------------------------------------------------------------------------

@app.route('/hr/dashboard')
@login_required
@role_required('HR')
def hr_dashboard():
    """Renders the central HR administration dashboard."""
    selected_employee_id = request.args.get('employee_id', 'all').strip()
    employees = User.query.order_by(User.role.asc(), User.employee_id.asc()).all()

    leave_requests_query = LeaveRequest.query.order_by(LeaveRequest.created_at.desc())
    attendance_query = Attendance.query.order_by(Attendance.date.desc(), Attendance.check_in.desc())

    selected_employee = None
    if selected_employee_id != 'all':
        if selected_employee_id.isdigit():
            selected_employee = User.query.get(int(selected_employee_id))
        if selected_employee:
            leave_requests_query = leave_requests_query.filter_by(user_id=selected_employee.id)
            attendance_query = attendance_query.filter_by(user_id=selected_employee.id)
        else:
            flash("Selected employee could not be found. Showing all records instead.", "warning")
            selected_employee_id = 'all'
    
    leave_requests = leave_requests_query.all()
    attendance_records = attendance_query.all()
    payroll_employees = [selected_employee] if selected_employee else employees
    today = datetime.now(timezone.utc).date()
    pending_leave_count = LeaveRequest.query.filter_by(status='Pending').count()
    checked_in_today_count = Attendance.query.filter_by(date=today).count()
    payroll_ready_count = User.query.filter(
        User.salary_structure.isnot(None),
        User.salary_structure != '',
        User.salary_structure != 'Pending HR Allocation'
    ).count()
    
    return render_template('hr_dashboard.html', 
                           employees=employees, 
                           leave_requests=leave_requests, 
                           attendance_records=attendance_records,
                           payroll_employees=payroll_employees,
                           selected_employee=selected_employee,
                           selected_employee_id=str(selected_employee.id) if selected_employee else 'all',
                           pending_leave_count=pending_leave_count,
                           checked_in_today_count=checked_in_today_count,
                           payroll_ready_count=payroll_ready_count)


@app.route('/hr/edit-employee/<int:user_id>', methods=['POST'])
@login_required
@role_required('HR')
def hr_edit_employee(user_id):
    """Processes HR updates to employee profile records."""
    emp = User.query.get_or_404(user_id)
    return_employee_id = request.form.get('return_employee_id', 'all').strip() or 'all'

    employee_id = request.form.get('employee_id', emp.employee_id).strip()
    email = request.form.get('email', emp.email).strip().lower()
    phone = request.form.get('phone', emp.phone or '').strip()
    address = request.form.get('address', emp.address or '').strip()
    job_title = request.form.get('job_title', emp.job_title or '').strip()
    salary_structure = request.form.get('salary_structure', emp.salary_structure or '').strip()
    new_role = request.form.get('role', emp.role).strip()

    if not employee_id or not email:
        flash("Employee ID and email are required.", "danger")
        return redirect(f"{url_for('hr_dashboard', employee_id=return_employee_id)}#employees-pane")

    if new_role not in ['Employee', 'HR']:
        flash("Invalid role selection.", "danger")
        return redirect(f"{url_for('hr_dashboard', employee_id=return_employee_id)}#employees-pane")

    existing_employee_id = User.query.filter(
        User.employee_id == employee_id,
        User.id != emp.id
    ).first()
    if existing_employee_id:
        flash("That employee ID already belongs to another user.", "danger")
        return redirect(f"{url_for('hr_dashboard', employee_id=return_employee_id)}#employees-pane")

    existing_email = User.query.filter(
        User.email == email,
        User.id != emp.id
    ).first()
    if existing_email:
        flash("That email address already belongs to another user.", "danger")
        return redirect(f"{url_for('hr_dashboard', employee_id=return_employee_id)}#employees-pane")

    if emp.id == current_user.id and new_role != 'HR':
        flash("You cannot remove your own HR access from the active account.", "danger")
        return redirect(f"{url_for('hr_dashboard', employee_id=return_employee_id)}#employees-pane")

    emp.employee_id = employee_id
    emp.email = email
    emp.phone = phone or None
    emp.address = address or None
    emp.job_title = job_title or 'Unassigned'
    emp.salary_structure = salary_structure or 'Pending HR Allocation'
    emp.role = new_role
        
    db.session.commit()
    flash(f"Profile for {emp.employee_id} successfully updated.", "success")
    return redirect(f"{url_for('hr_dashboard', employee_id=emp.id)}#employees-pane")


@app.route('/hr/update-payroll/<int:user_id>', methods=['POST'])
@login_required
@role_required('HR')
def hr_update_payroll(user_id):
    """Processes HR payroll updates while preserving employee-scoped navigation."""
    emp = User.query.get_or_404(user_id)
    return_employee_id = request.form.get('return_employee_id', 'all').strip() or 'all'
    salary_structure = request.form.get('salary_structure', '').strip()

    if not salary_structure:
        flash("Salary structure is required to keep payroll records accurate.", "danger")
        return redirect(f"{url_for('hr_dashboard', employee_id=return_employee_id)}#payroll-pane")

    emp.salary_structure = salary_structure
    try:
        db.session.commit()
        flash(f"Payroll for {emp.employee_id} updated successfully.", "success")
        return redirect(f"{url_for('hr_dashboard', employee_id=emp.id)}#payroll-pane")
    except SQLAlchemyError:
        db.session.rollback()
        flash("Payroll could not be updated because the database write failed. Please try again.", "danger")
        return redirect(f"{url_for('hr_dashboard', employee_id=return_employee_id)}#payroll-pane")


@app.route('/hr/process-leave/<int:request_id>', methods=['POST'])
@login_required
@role_required('HR')
def hr_process_leave(request_id):
    """Handles HR approval or rejection of employee leave requests."""
    req = LeaveRequest.query.get_or_404(request_id)
    
    new_status = request.form.get('status')
    hr_comments = request.form.get('hr_comments', '').strip()
    
    if new_status in ['Approved', 'Rejected']:
        if new_status == 'Approved':
            conflicts = find_attendance_conflicts(req.user_id, req.start_date, req.end_date)
            if conflicts:
                flash("This leave overlaps with existing present or half-day attendance and cannot be approved.", "danger")
                return redirect(f"{url_for('hr_dashboard', employee_id=req.user_id)}#leaves-pane")

        req.status = new_status
        req.hr_comments = hr_comments or None
        sync_leave_attendance_records(req)
        db.session.commit()
        
        flash(f"Leave request for {req.user.employee_id} has been {new_status.lower()}.", "success")
    else:
        flash("Invalid status update requested.", "danger")
        
    return redirect(f"{url_for('hr_dashboard', employee_id=req.user_id)}#leaves-pane")





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
