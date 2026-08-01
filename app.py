import os
import csv
import secrets
from io import StringIO
from datetime import datetime, timedelta

import pytz
from flask import (
    Flask, jsonify, render_template, redirect, url_for,
    request, flash, abort, send_from_directory, Response
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from werkzeug.utils import secure_filename

# AD / LDAP
from ldap3 import Server, Connection, ALL, SIMPLE, NTLM, SUBTREE
from ldap3.core.exceptions import LDAPException


app = Flask(__name__)


def get_or_create_secret_key():
    """Use SECRET_KEY from the environment if set; otherwise persist a
    randomly generated one in instance/secret_key so sessions survive
    restarts without a hardcoded key living in source control."""
    env_key = os.environ.get('SECRET_KEY')
    if env_key:
        return env_key

    os.makedirs(app.instance_path, exist_ok=True)
    key_path = os.path.join(app.instance_path, 'secret_key')
    if os.path.exists(key_path):
        with open(key_path, 'r') as f:
            return f.read().strip()

    key = secrets.token_hex(32)
    with open(key_path, 'w') as f:
        f.write(key)
    return key


# -----------------------------
# Config
# -----------------------------
app.config['SECRET_KEY'] = get_or_create_secret_key()

_database_uri = os.environ.get('DATABASE_URI', 'sqlite:///ticketapp.db')
# Render (and Heroku before it) hand out connection strings starting with
# "postgres://", but SQLAlchemy 2.x only accepts the "postgresql://" scheme.
if _database_uri.startswith('postgres://'):
    _database_uri = _database_uri.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = _database_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

login_manager.login_view = 'login'

# Riyadh timezone configuration
RIYADH_TZ = pytz.timezone('Asia/Riyadh')


def get_riyadh_time_naive():
    return datetime.now(RIYADH_TZ).replace(tzinfo=None)


def format_riyadh_datetime(dt):
    if dt is None:
        return 'N/A'
    if dt.tzinfo is None:
        riyadh_dt = RIYADH_TZ.localize(dt)
    else:
        riyadh_dt = dt.astimezone(RIYADH_TZ)
    return riyadh_dt.strftime('%Y-%m-%d %H:%M')


# -----------------------------
# Models
# -----------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)

    role = db.Column(db.String(20), nullable=False)  # agent / supervisor / manager / it_staff / admin
    room = db.Column(db.String(20), nullable=False)

    profile_picture = db.Column(db.String(200), nullable=True)

    # local | ad
    auth_source = db.Column(db.String(20), default='local', nullable=False)

    def check_password(self, password: str) -> bool:
        return bcrypt.check_password_hash(self.password_hash, password)


class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    submitter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room = db.Column(db.String(20), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)

    file_name = db.Column(db.String(200), nullable=True)  # backward compatibility
    status = db.Column(db.String(20), default='Open')

    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    ip_address = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=get_riyadh_time_naive)
    updated_at = db.Column(db.DateTime, default=get_riyadh_time_naive, onupdate=get_riyadh_time_naive)

    submitter = db.relationship('User', foreign_keys=[submitter_id], backref='submitted_tickets')
    assigned_to = db.relationship('User', foreign_keys=[assigned_to_id], backref='assigned_tickets')


class TicketComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comment = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=get_riyadh_time_naive)

    ticket = db.relationship('Ticket', backref=db.backref('comments', lazy=True, cascade='all, delete-orphan'))
    user = db.relationship('User')


class TicketAttachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=get_riyadh_time_naive)

    ticket = db.relationship('Ticket', backref=db.backref('attachments', lazy=True, cascade='all, delete-orphan'))
    uploaded_by = db.relationship('User')


class TicketReassignmentRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    requested_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Pending')
    created_at = db.Column(db.DateTime, default=get_riyadh_time_naive)

    ticket = db.relationship('Ticket', backref=db.backref('reassignment_requests', lazy=True, cascade='all, delete-orphan'))
    requested_by = db.relationship('User')


class TicketAssignmentSuggestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    suggested_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='Pending', nullable=False)  # Pending / Accepted / Rejected
    rejection_reason = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=get_riyadh_time_naive)

    ticket = db.relationship('Ticket', backref=db.backref('assignment_suggestions', lazy=True, cascade='all, delete-orphan'))
    suggested_by = db.relationship('User', foreign_keys=[suggested_by_id])
    target_user = db.relationship('User', foreign_keys=[target_user_id])


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(50), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=get_riyadh_time_naive)

    user = db.relationship('User', backref=db.backref('notifications', lazy=True))
    ticket = db.relationship('Ticket', backref=db.backref('notifications', lazy=True))


class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    asset_type = db.Column(db.String(50), nullable=False)  # TV, PC, Laptop, Printer, ...
    label_name = db.Column(db.String(100), nullable=True)
    serial_number = db.Column(db.String(100), unique=True, nullable=False)

    # Location
    zone = db.Column(db.String(50), nullable=True)
    office = db.Column(db.String(50), nullable=True)
    table_number = db.Column(db.String(50), nullable=True)

    # Specs / optional info
    mac_address = db.Column(db.String(50), nullable=True)
    cpu = db.Column(db.String(100), nullable=True)
    ram = db.Column(db.String(50), nullable=True)
    model = db.Column(db.String(100), nullable=True)
    manufacturer = db.Column(db.String(100), nullable=True)
    product_number = db.Column(db.String(100), nullable=True)

    status = db.Column(db.String(20), default='Working', nullable=False)  # Working / Broken / Repaired

    added_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=get_riyadh_time_naive)
    updated_at = db.Column(db.DateTime, default=get_riyadh_time_naive, onupdate=get_riyadh_time_naive)

    added_by = db.relationship('User')

    def to_qr_text(self):
        lines = [f"ZENTRA - {self.asset_type}"]
        if self.label_name:
            lines.append(f"الاسم: {self.label_name}")
        lines.append(f"الرقم التسلسلي: {self.serial_number}")
        lines.append(f"الحالة: {self.status}")
        if self.zone:
            lines.append(f"المنطقة: {self.zone}")
        if self.office:
            lines.append(f"المكتب: {self.office}")
        if self.table_number:
            lines.append(f"الطاولة: {self.table_number}")
        if self.mac_address:
            lines.append(f"MAC: {self.mac_address}")
        if self.cpu:
            lines.append(f"CPU: {self.cpu}")
        if self.ram:
            lines.append(f"RAM: {self.ram}")
        if self.model:
            lines.append(f"الموديل: {self.model}")
        if self.manufacturer:
            lines.append(f"الشركة المصنعة: {self.manufacturer}")
        if self.product_number:
            lines.append(f"رقم المنتج: {self.product_number}")
        return "\n".join(lines)


IT_TEAM_ROLES = ['it_staff', 'admin']
# it_admin is a supervisor role: not an assignee/roster member (not in IT_TEAM_ROLES),
# but can chat 1:1 and post to the team channel like the team it oversees.
IT_CHAT_ROLES = IT_TEAM_ROLES + ['it_admin']


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # NULL = team channel post
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=get_riyadh_time_naive)
    is_read = db.Column(db.Boolean, default=False)  # only meaningful for DMs (recipient_id set)

    sender = db.relationship('User', foreign_keys=[sender_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])


class ChannelReadMarker(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    last_seen_at = db.Column(db.DateTime, default=get_riyadh_time_naive)

    user = db.relationship('User')


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    is_team_wide = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=get_riyadh_time_naive)

    created_by = db.relationship('User')


class TaskAssignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='Open', nullable=False)  # Open / In Progress / Escalated / Done
    created_at = db.Column(db.DateTime, default=get_riyadh_time_naive)
    updated_at = db.Column(db.DateTime, default=get_riyadh_time_naive, onupdate=get_riyadh_time_naive)

    task = db.relationship('Task', backref=db.backref('assignments', lazy=True, cascade='all, delete-orphan'))
    assignee = db.relationship('User')


class TaskDelegationRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_assignment_id = db.Column(db.Integer, db.ForeignKey('task_assignment.id'), nullable=False)
    requested_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Pending', nullable=False)  # Pending / Accepted / Rejected
    created_at = db.Column(db.DateTime, default=get_riyadh_time_naive)

    task_assignment = db.relationship('TaskAssignment', backref=db.backref('delegation_requests', lazy=True, cascade='all, delete-orphan'))
    requested_by = db.relationship('User', foreign_keys=[requested_by_id])
    target_user = db.relationship('User', foreign_keys=[target_user_id])


class TaskComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_assignment_id = db.Column(db.Integer, db.ForeignKey('task_assignment.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comment_type = db.Column(db.String(20), nullable=False)  # question / answer / completion / note
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=get_riyadh_time_naive)

    task_assignment = db.relationship('TaskAssignment', backref=db.backref('comments', lazy=True, cascade='all, delete-orphan'))
    user = db.relationship('User')


class TaskAttachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_assignment_id = db.Column(db.Integer, db.ForeignKey('task_assignment.id'), nullable=False)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=get_riyadh_time_naive)

    task_assignment = db.relationship('TaskAssignment', backref=db.backref('attachments', lazy=True, cascade='all, delete-orphan'))
    uploaded_by = db.relationship('User')


class UserPresence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    last_seen_at = db.Column(db.DateTime, default=get_riyadh_time_naive)

    user = db.relationship('User')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# -----------------------------
# Upload config
# -----------------------------
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024 * 1024  # 1GB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'docx', 'xlsx', 'txt', 'gif'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# -----------------------------
# Notification Helpers
# -----------------------------
def create_notification(user_id, ticket_id, title, message, notification_type):
    notification = Notification(
        user_id=user_id,
        ticket_id=ticket_id,
        title=title,
        message=message,
        notification_type=notification_type
    )
    db.session.add(notification)


def notify_ticket_status_change(ticket, old_status, new_status, changed_by):
    users_to_notify = []
    if ticket.submitter_id != changed_by.id:
        users_to_notify.append(ticket.submitter_id)
    if ticket.assigned_to_id and ticket.assigned_to_id != changed_by.id:
        users_to_notify.append(ticket.assigned_to_id)

    supervisors = User.query.filter(
        User.room == ticket.room,
        User.role.in_(['supervisor', 'manager'])
    ).all()

    for supervisor in supervisors:
        if supervisor.id != changed_by.id:
            users_to_notify.append(supervisor.id)

    for uid in set(users_to_notify):
        create_notification(
            user_id=uid,
            ticket_id=ticket.id,
            title=f"Ticket #{ticket.id} Status Changed",
            message=f"Status changed from '{old_status}' to '{new_status}' by {changed_by.full_name}",
            notification_type='status_change'
        )


def notify_ticket_assignment(ticket, assigned_by):
    users_to_notify = []
    if ticket.assigned_to_id:
        users_to_notify.append(ticket.assigned_to_id)
    if ticket.submitter_id != assigned_by.id:
        users_to_notify.append(ticket.submitter_id)

    for uid in set(users_to_notify):
        create_notification(
            user_id=uid,
            ticket_id=ticket.id,
            title=f"Ticket #{ticket.id} Assigned",
            message=f"Ticket has been assigned to {ticket.assigned_to.full_name}" if ticket.assigned_to else "Ticket assignment updated",
            notification_type='assignment'
        )


def notify_new_comment(ticket, comment_text, commenter):
    users_to_notify = []
    if ticket.submitter_id != commenter.id:
        users_to_notify.append(ticket.submitter_id)
    if ticket.assigned_to_id and ticket.assigned_to_id != commenter.id:
        users_to_notify.append(ticket.assigned_to_id)

    previous_commenters = db.session.query(TicketComment.user_id).filter(
        TicketComment.ticket_id == ticket.id,
        TicketComment.user_id != commenter.id
    ).distinct().all()

    for (uid,) in previous_commenters:
        users_to_notify.append(uid)

    for uid in set(users_to_notify):
        create_notification(
            user_id=uid,
            ticket_id=ticket.id,
            title=f"New Comment on Ticket #{ticket.id}",
            message=f"{commenter.full_name} added a comment: {comment_text[:100]}{'...' if len(comment_text) > 100 else ''}",
            notification_type='comment'
        )


def notify_escalation(ticket, escalated_by):
    admins = User.query.filter_by(role='admin').all()
    for admin in admins:
        create_notification(
            user_id=admin.id,
            ticket_id=ticket.id,
            title=f"Ticket #{ticket.id} Escalated",
            message=f"Ticket escalated by {escalated_by.full_name} - requires admin attention",
            notification_type='escalation'
        )


@app.template_filter('riyadh_datetime')
def riyadh_datetime_filter(dt):
    return format_riyadh_datetime(dt)


# -----------------------------
# AD / LDAP config
# -----------------------------
AD_SERVER = os.environ.get("AD_SERVER", "192.168.101.250")
AD_DOMAIN = os.environ.get("AD_DOMAIN", "exp.local")
AD_BASE_DN = os.environ.get("AD_BASE_DN", "DC=exp,DC=local")
AD_NETBIOS = os.environ.get("AD_NETBIOS", "EXP")
AD_USE_SSL = os.environ.get("AD_USE_SSL", "false").lower() == "true"

# Optional: allow only users in a group DN (leave empty to disable)
AD_REQUIRE_GROUP_DN = os.environ.get("AD_REQUIRE_GROUP_DN", "").strip()

# Defaults for new AD users when first login
DEFAULT_AD_ROLE = os.environ.get("DEFAULT_AD_ROLE", "agent")
DEFAULT_AD_ROOM = os.environ.get("DEFAULT_AD_ROOM", "HQ")


def ad_authenticate_and_fetch(username: str, password: str):
    """
    Returns (True, attrs_dict) if AD auth succeeds, else (False, reason).
    attrs_dict: full_name, email, samaccountname
    """
    if not username or not password:
        return False, "Missing username/password"

    server = Server(AD_SERVER, get_info=ALL, use_ssl=AD_USE_SSL)

    # Try SIMPLE bind with UPN first: user@domain
    upn = username if "@" in username else f"{username}@{AD_DOMAIN}"
    try:
        with Connection(server, user=upn, password=password, authentication=SIMPLE, auto_bind=True) as conn:
            user_filter = f"(|(sAMAccountName={username})(userPrincipalName={upn}))"
            conn.search(
                search_base=AD_BASE_DN,
                search_filter=f"(&(objectClass=user){user_filter})",
                search_scope=SUBTREE,
                attributes=["displayName", "mail", "sAMAccountName", "memberOf"]
            )
            if not conn.entries:
                return False, "AD user not found after bind"

            entry = conn.entries[0]
            member_of = entry.memberOf.values if "memberOf" in entry else []

            if AD_REQUIRE_GROUP_DN and AD_REQUIRE_GROUP_DN not in member_of:
                return False, "User not in required group"

            attrs = {
                "full_name": str(entry.displayName.value) if entry.displayName.value else username,
                "email": str(entry.mail.value) if entry.mail.value else f"{username}@{AD_DOMAIN}",
                "samaccountname": str(entry.sAMAccountName.value) if entry.sAMAccountName.value else username
            }
            return True, attrs
    except LDAPException:
        pass

    # Try NTLM bind: NETBIOS\username
    try:
        ntlm_user = f"{AD_NETBIOS}\\{username}"
        with Connection(server, user=ntlm_user, password=password, authentication=NTLM, auto_bind=True) as conn:
            conn.search(
                search_base=AD_BASE_DN,
                search_filter=f"(&(objectClass=user)(sAMAccountName={username}))",
                search_scope=SUBTREE,
                attributes=["displayName", "mail", "sAMAccountName", "memberOf"]
            )
            if not conn.entries:
                return False, "AD user not found after NTLM bind"

            entry = conn.entries[0]
            member_of = entry.memberOf.values if "memberOf" in entry else []

            if AD_REQUIRE_GROUP_DN and AD_REQUIRE_GROUP_DN not in member_of:
                return False, "User not in required group"

            attrs = {
                "full_name": str(entry.displayName.value) if entry.displayName.value else username,
                "email": str(entry.mail.value) if entry.mail.value else f"{username}@{AD_DOMAIN}",
                "samaccountname": str(entry.sAMAccountName.value) if entry.sAMAccountName.value else username
            }
            return True, attrs
    except LDAPException:
        pass

    return False, "AD authentication failed"


def get_or_create_local_user_from_ad(ad_attrs: dict):
    sam = ad_attrs["samaccountname"]
    user = User.query.filter_by(username=sam).first()
    if user:
        user.full_name = ad_attrs.get("full_name", user.full_name)
        user.email = ad_attrs.get("email", user.email)
        user.auth_source = "ad"
        db.session.commit()
        return user

    random_pw_hash = bcrypt.generate_password_hash(os.urandom(24).hex()).decode('utf-8')
    user = User(
        username=sam,
        password_hash=random_pw_hash,
        full_name=ad_attrs.get("full_name", sam),
        email=ad_attrs.get("email", f"{sam}@{AD_DOMAIN}"),
        role=DEFAULT_AD_ROLE,
        room=DEFAULT_AD_ROOM,
        auth_source="ad"
    )
    db.session.add(user)
    db.session.commit()
    return user


# -----------------------------
# Routes
# -----------------------------
@app.route('/')
@login_required
def dashboard():
    user = current_user
    filter_type = request.args.get('filter', 'new')
    status_filter = request.args.get('status')
    date_filter = request.args.get('date')
    search_query = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 5

    tickets_query = Ticket.query

    if user.role == 'agent':
        tickets_query = tickets_query.filter_by(submitter_id=user.id)
    elif user.role in ['supervisor', 'manager']:
        tickets_query = tickets_query.filter_by(room=user.room)
    elif user.role in ['it_staff', 'admin', 'it_admin']:
        if filter_type == 'assigned':
            tickets_query = tickets_query.filter_by(assigned_to_id=user.id)
        elif filter_type == 'new':
            tickets_query = tickets_query.filter_by(assigned_to_id=None)

    if date_filter:
        try:
            date_obj = datetime.strptime(date_filter, '%Y-%m-%d')
            start_naive = RIYADH_TZ.localize(date_obj.replace(hour=0, minute=0, second=0)).replace(tzinfo=None)
            end_naive = RIYADH_TZ.localize(date_obj.replace(hour=23, minute=59, second=59)).replace(tzinfo=None)
            tickets_query = tickets_query.filter(Ticket.created_at.between(start_naive, end_naive))
        except ValueError:
            flash("Invalid date format", "danger")

    if search_query:
        like_pattern = f"%{search_query}%"
        search_filters = [
            Ticket.description.ilike(like_pattern),
            Ticket.category.ilike(like_pattern),
        ]
        if search_query.isdigit():
            search_filters.append(Ticket.id == int(search_query))
        tickets_query = tickets_query.filter(db.or_(*search_filters))

    # Status breakdown reflects the current scope/search/date (but not the
    # status filter itself) so the tiles stay usable as quick filters.
    status_counts = {
        status: tickets_query.filter_by(status=status).count()
        for status in ['Open', 'In Progress', 'Escalated', 'Resolved', 'Closed']
    }
    status_counts['Total'] = tickets_query.count()

    if status_filter:
        tickets_query = tickets_query.filter_by(status=status_filter)

    pagination = tickets_query.order_by(Ticket.created_at.desc()).paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )

    unread_notifications_count = Notification.query.filter_by(
        user_id=user.id,
        is_read=False
    ).count()

    return render_template(
        'dashboard.html',
        tickets=pagination.items,
        pagination=pagination,
        user=user,
        status_counts=status_counts,
        unread_notifications_count=unread_notifications_count
    )


@app.route('/search')
@login_required
def global_search():
    query = request.args.get('q', '').strip()
    user = current_user

    tickets_results = []
    users_results = []
    assets_results = []

    if query:
        like_pattern = f"%{query}%"

        tickets_query = Ticket.query
        if user.role == 'agent':
            tickets_query = tickets_query.filter_by(submitter_id=user.id)
        elif user.role in ['supervisor', 'manager']:
            tickets_query = tickets_query.filter_by(room=user.room)

        ticket_filters = [
            Ticket.description.ilike(like_pattern),
            Ticket.category.ilike(like_pattern),
        ]
        if query.isdigit():
            ticket_filters.append(Ticket.id == int(query))
        tickets_results = tickets_query.filter(db.or_(*ticket_filters)) \
            .order_by(Ticket.created_at.desc()).limit(25).all()

        if user.role in ['admin', 'it_staff']:
            users_results = User.query.filter(db.or_(
                User.username.ilike(like_pattern),
                User.full_name.ilike(like_pattern),
                User.email.ilike(like_pattern)
            )).limit(25).all()

        if user.role in ['admin', 'it_staff', 'manager', 'supervisor']:
            assets_results = Asset.query.filter(db.or_(
                Asset.serial_number.ilike(like_pattern),
                Asset.label_name.ilike(like_pattern),
                Asset.model.ilike(like_pattern),
                Asset.manufacturer.ilike(like_pattern),
                Asset.product_number.ilike(like_pattern)
            )).limit(25).all()

    unread_notifications_count = Notification.query.filter_by(
        user_id=user.id, is_read=False
    ).count()

    return render_template(
        'search_results.html',
        query=query,
        tickets=tickets_results,
        users=users_results,
        assets=assets_results,
        user=user,
        unread_notifications_count=unread_notifications_count
    )


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = (request.form.get('username') or "").strip()
        password = request.form.get('password') or ""

        # 1) Try LOCAL users first (non-AD)
        user = User.query.filter_by(username=username).first()
        if user and user.auth_source != "ad":
            if user.check_password(password):
                login_user(user)
                return redirect(url_for('dashboard'))
            # Invalid credentials - redirect with error parameter
            return redirect(url_for('login', error='invalid_credentials'))

        # 2) Try AD login - wrap in try-except to catch MD4/NTLM errors
        try:
            ok, data_or_reason = ad_authenticate_and_fetch(username, password)
            if ok:
                local_user = get_or_create_local_user_from_ad(data_or_reason)
                login_user(local_user)
                return redirect(url_for('dashboard'))
        except ValueError as e:
            # MD4 hash error in Python 3.13+ - AD authentication not available
            if 'MD4' in str(e):
                flash('AD authentication unavailable. Please contact IT support or use local account.', 'warning')
                return redirect(url_for('login'))
            raise
        except Exception as e:
            # Log the error but don't expose details to user
            print(f"AD authentication error: {e}")

        # Login failed - redirect with error parameter
        return redirect(url_for('login', error='invalid_credentials'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/notifications')
@login_required
def notifications():
    page = request.args.get('page', 1, type=int)
    notifications_pg = Notification.query.filter_by(user_id=current_user.id) \
        .order_by(Notification.created_at.desc()) \
        .paginate(page=page, per_page=20, error_out=False)

    return render_template('notifications.html', notifications=notifications_pg, user=current_user)


@app.route('/notifications/mark_read/<int:notification_id>')
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.filter_by(
        id=notification_id,
        user_id=current_user.id
    ).first_or_404()

    notification.is_read = True
    db.session.commit()
    return redirect(url_for('ticket_detail', ticket_id=notification.ticket_id))


@app.route('/notifications/mark_all_read')
@login_required
def mark_all_notifications_read():
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
    db.session.commit()
    flash('All notifications marked as read.', 'success')
    return redirect(url_for('notifications'))


@app.route('/api/notifications/count')
@login_required
def get_notification_count():
    count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    return jsonify({'count': count})


@app.route('/api/notifications/recent')
@login_required
def get_recent_notifications():
    notifications = Notification.query.filter_by(user_id=current_user.id) \
        .order_by(Notification.created_at.desc()) \
        .limit(5).all()

    return jsonify([{
        'id': n.id,
        'title': n.title,
        'message': n.message,
        'type': n.notification_type,
        'is_read': n.is_read,
        'created_at': format_riyadh_datetime(n.created_at),
        'ticket_id': n.ticket_id
    } for n in notifications])


@app.route('/profile')
@login_required
def profile():
    total_tickets = Ticket.query.filter_by(submitter_id=current_user.id).count()
    open_tickets = Ticket.query.filter_by(submitter_id=current_user.id, status='Open').count()
    resolved_tickets = Ticket.query.filter_by(submitter_id=current_user.id, status='Resolved').count()

    return render_template(
        'profile.html',
        user=current_user,
        total_tickets=total_tickets,
        open_tickets=open_tickets,
        resolved_tickets=resolved_tickets
    )


@app.route('/profile/upload_picture', methods=['POST'])
@login_required
def upload_profile_picture():
    if 'profile_picture' not in request.files:
        return jsonify({'success': False, 'message': 'No file selected'}), 400

    file = request.files['profile_picture']
    if not file or file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400

    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    if not ('.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in allowed_extensions):
        return jsonify({'success': False, 'message': 'Unsupported file type'}), 400

    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)
    if file_size > 5 * 1024 * 1024:
        return jsonify({'success': False, 'message': 'File too large (max 5MB)'}), 400

    profile_pictures_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pictures')
    os.makedirs(profile_pictures_dir, exist_ok=True)

    filename = secure_filename(file.filename)
    unique_filename = f"user_{current_user.id}_{int(datetime.now().timestamp())}_{filename}"
    filepath = os.path.join(profile_pictures_dir, unique_filename)

    try:
        # delete old if exists
        if current_user.profile_picture:
            old_path = os.path.join(app.config['UPLOAD_FOLDER'], current_user.profile_picture)
            if os.path.exists(old_path):
                os.remove(old_path)

        file.save(filepath)
        current_user.profile_picture = f"profile_pictures/{unique_filename}"
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Profile picture updated',
            'image_url': url_for('uploads', filename=current_user.profile_picture)
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/submit_ticket', methods=['GET', 'POST'])
@login_required
def submit_ticket():
    if request.method == 'POST':
        category = request.form.get('category', '').strip()
        description = request.form.get('description', '').strip()

        if request.headers.get('X-Forwarded-For'):
            ip_address = request.headers.get('X-Forwarded-For').split(',')[0].strip()
        else:
            ip_address = request.remote_addr

        if not category or not description:
            flash('Category and description are required.', 'danger')
            return redirect(url_for('submit_ticket'))

        ticket = Ticket(
            submitter_id=current_user.id,
            room=current_user.room,
            category=category,
            description=description,
            status='Open',
            ip_address=ip_address
        )
        db.session.add(ticket)
        db.session.commit()

        # multiple files
        files = request.files.getlist('files')
        uploaded_files = []

        if files:
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            ticket_folder = os.path.join(app.config['UPLOAD_FOLDER'], f'ticket_{ticket.id}')
            os.makedirs(ticket_folder, exist_ok=True)

            for file in files:
                if file and file.filename and allowed_file(file.filename):
                    file.seek(0, 2)
                    file_size = file.tell()
                    file.seek(0)

                    if file_size > 100 * 1024 * 1024:
                        flash(f'File {file.filename} too large (max 100MB)', 'warning')
                        continue

                    filename = secure_filename(file.filename)
                    unique_filename = f"{int(datetime.now().timestamp())}_{filename}"
                    filepath = os.path.join(ticket_folder, unique_filename)
                    try:
                        file.save(filepath)
                        attachment = TicketAttachment(
                            ticket_id=ticket.id,
                            uploaded_by_id=current_user.id,
                            filename=f'ticket_{ticket.id}/{unique_filename}'
                        )
                        db.session.add(attachment)
                        uploaded_files.append(filename)

                        if not ticket.file_name:
                            ticket.file_name = f'ticket_{ticket.id}/{unique_filename}'

                    except Exception as e:
                        flash(f'Upload failed for {filename}: {str(e)}', 'danger')

            db.session.commit()

        # notify IT staff + supervisors
        it_staff = User.query.filter_by(role='it_staff').all()
        supervisors = User.query.filter(
            User.room == ticket.room,
            User.role.in_(['supervisor', 'manager'])
        ).all()

        for u in set(it_staff + supervisors):
            if u.id != current_user.id:
                create_notification(
                    user_id=u.id,
                    ticket_id=ticket.id,
                    title=f"New Ticket #{ticket.id} Submitted",
                    message=f"New {category} ticket submitted by {current_user.full_name} from {ticket.room}",
                    notification_type='new_ticket'
                )

        db.session.commit()
        flash('Ticket submitted successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('submit_ticket.html', user=current_user)


@app.route('/ticket/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def ticket_detail(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    user = current_user

    if user.role == 'agent' and ticket.submitter_id != user.id:
        return "Access Denied", 403
    if user.role == 'supervisor' and ticket.room != user.room:
        return "Access Denied", 403

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'add_comment':
            comment_text = (request.form.get('comment') or '').strip()
            if comment_text:
                new_comment = TicketComment(ticket_id=ticket.id, user_id=user.id, comment=comment_text)
                db.session.add(new_comment)
                db.session.commit()
                notify_new_comment(ticket, comment_text, user)
                db.session.commit()
                flash('Comment added successfully.', 'success')

        elif action == 'change_status':
            if user.role not in ['admin', 'it_staff']:
                flash('You are not authorized to change ticket status.', 'danger')
            else:
                old_status = ticket.status
                new_status = request.form.get('status')
                if new_status in ['Open', 'In Progress', 'Escalated', 'Resolved', 'Closed']:
                    ticket.status = new_status
                    db.session.commit()
                    if old_status != new_status:
                        notify_ticket_status_change(ticket, old_status, new_status, user)
                        db.session.commit()
                    flash('Ticket status updated successfully.', 'success')
                else:
                    flash('Invalid status value.', 'danger')

        elif action == 'take_ticket':
            if user.role not in ['admin', 'it_staff']:
                flash('You are not authorized to take this ticket.', 'danger')
            elif ticket.assigned_to_id is not None or ticket.status == 'Escalated':
                flash('This ticket is no longer unassigned.', 'warning')
            else:
                ticket.assigned_to_id = user.id
                ticket.status = 'In Progress'
                db.session.commit()
                notify_ticket_assignment(ticket, user)
                db.session.commit()
                flash('Ticket assigned to you.', 'success')

        elif action == 'suggest_assignment':
            if user.role not in ['admin', 'it_staff']:
                flash('You are not authorized to suggest an assignment.', 'danger')
            elif ticket.assigned_to_id is not None or ticket.status == 'Escalated':
                flash('This ticket is no longer unassigned.', 'warning')
            else:
                target_user_id = request.form.get('target_user_id', type=int)
                target = User.query.get(target_user_id) if target_user_id else None
                if not target or target.role not in ['it_staff', 'admin'] or target.id == user.id:
                    flash('Please choose a valid teammate to suggest.', 'danger')
                else:
                    existing = TicketAssignmentSuggestion.query.filter_by(ticket_id=ticket.id, status='Pending').first()
                    if existing:
                        flash('There is already a pending suggestion for this ticket.', 'warning')
                    else:
                        db.session.add(TicketAssignmentSuggestion(
                            ticket_id=ticket.id,
                            suggested_by_id=user.id,
                            target_user_id=target.id
                        ))
                        db.session.commit()
                        create_notification(
                            user_id=target.id,
                            ticket_id=ticket.id,
                            title=f"Ticket #{ticket.id} Suggested to You",
                            message=f"{user.full_name} suggests you take ticket #{ticket.id}",
                            notification_type='assignment_suggested'
                        )
                        db.session.commit()
                        flash('Suggestion sent.', 'success')

        elif action == 'handle_assignment_suggestion':
            suggestion_id = request.form.get('suggestion_id')
            decision = request.form.get('decision')
            suggestion = TicketAssignmentSuggestion.query.get(suggestion_id)

            if (not suggestion) or suggestion.ticket_id != ticket.id or suggestion.status != 'Pending' or suggestion.target_user_id != user.id:
                flash('Invalid suggestion.', 'danger')
            elif decision == 'accept':
                if ticket.assigned_to_id is not None:
                    flash('This ticket has already been assigned.', 'warning')
                else:
                    ticket.assigned_to_id = user.id
                    ticket.status = 'In Progress'
                    suggestion.status = 'Accepted'
                    db.session.commit()
                    notify_ticket_assignment(ticket, user)
                    create_notification(
                        user_id=suggestion.suggested_by_id,
                        ticket_id=ticket.id,
                        title=f"Suggestion Accepted for Ticket #{ticket.id}",
                        message=f"{user.full_name} accepted your suggestion and took ticket #{ticket.id}",
                        notification_type='assignment_suggestion_accepted'
                    )
                    db.session.commit()
                    flash('Ticket assigned to you.', 'success')
            elif decision == 'reject':
                reason = (request.form.get('rejection_reason') or '').strip()
                if not reason:
                    flash('Please provide a reason for declining.', 'danger')
                else:
                    suggestion.status = 'Rejected'
                    suggestion.rejection_reason = reason
                    db.session.commit()
                    create_notification(
                        user_id=suggestion.suggested_by_id,
                        ticket_id=ticket.id,
                        title=f"Suggestion Declined for Ticket #{ticket.id}",
                        message=f"{user.full_name} declined: {reason[:150]}{'...' if len(reason) > 150 else ''}",
                        notification_type='assignment_suggestion_rejected'
                    )
                    db.session.commit()
                    flash('Suggestion declined.', 'info')
            else:
                flash('Invalid decision.', 'danger')

        elif action == 'request_reassignment':
            if user.role not in ['admin', 'it_staff']:
                flash('You are not authorized to request reassignment.', 'danger')
            elif not ticket.assigned_to_id or ticket.assigned_to_id == user.id:
                flash('Ticket is not assigned to another user.', 'warning')
            else:
                reason = (request.form.get('reason') or '').strip()
                if not reason:
                    flash('Reason is required for reassignment request.', 'danger')
                else:
                    existing_request = TicketReassignmentRequest.query.filter_by(
                        ticket_id=ticket.id,
                        requested_by_id=user.id,
                        status='Pending'
                    ).first()
                    if existing_request:
                        flash('You already have a pending reassignment request for this ticket.', 'warning')
                    else:
                        req = TicketReassignmentRequest(
                            ticket_id=ticket.id,
                            requested_by_id=user.id,
                            reason=reason,
                            status='Pending'
                        )
                        db.session.add(req)
                        db.session.commit()

                        if ticket.assigned_to_id:
                            create_notification(
                                user_id=ticket.assigned_to_id,
                                ticket_id=ticket.id,
                                title=f"Reassignment Request for Ticket #{ticket.id}",
                                message=f"{user.full_name} requests reassignment: {reason[:100]}{'...' if len(reason) > 100 else ''}",
                                notification_type='reassignment_request'
                            )
                            db.session.commit()

                        flash('Reassignment request submitted.', 'success')

        elif action == 'handle_reassignment':
            if user.id != ticket.assigned_to_id:
                flash('You are not authorized to handle reassignment requests.', 'danger')
            else:
                req_id = request.form.get('request_id')
                decision = request.form.get('decision')
                reassignment_request = TicketReassignmentRequest.query.get(req_id)

                if (not reassignment_request) or reassignment_request.ticket_id != ticket.id or reassignment_request.status != 'Pending':
                    flash('Invalid reassignment request.', 'danger')
                else:
                    if decision == 'accept':
                        ticket.assigned_to_id = reassignment_request.requested_by_id
                        ticket.status = 'In Progress'
                        reassignment_request.status = 'Accepted'
                        db.session.commit()

                        notify_ticket_assignment(ticket, user)
                        create_notification(
                            user_id=reassignment_request.requested_by_id,
                            ticket_id=ticket.id,
                            title=f"Reassignment Accepted for Ticket #{ticket.id}",
                            message=f"Your reassignment request was accepted by {user.full_name}",
                            notification_type='reassignment_accepted'
                        )
                        db.session.commit()
                        flash('Reassignment accepted.', 'success')

                    elif decision == 'reject':
                        reassignment_request.status = 'Rejected'
                        db.session.commit()

                        create_notification(
                            user_id=reassignment_request.requested_by_id,
                            ticket_id=ticket.id,
                            title=f"Reassignment Rejected for Ticket #{ticket.id}",
                            message=f"Your reassignment request was rejected by {user.full_name}",
                            notification_type='reassignment_rejected'
                        )
                        db.session.commit()
                        flash('Reassignment rejected.', 'info')

        elif action == 'escalate_ticket':
            if user.role == 'it_staff' and ticket.assigned_to_id == user.id:
                ticket.status = 'Escalated'
                ticket.assigned_to_id = None
                db.session.commit()
                notify_escalation(ticket, user)
                db.session.commit()
                flash('Ticket escalated to admin.', 'info')
            else:
                flash('You are not authorized to escalate this ticket.', 'danger')

        elif action == 'accept_escalated_ticket':
            if user.role == 'admin' and ticket.status == 'Escalated':
                ticket.assigned_to_id = user.id
                ticket.status = 'In Progress'
                db.session.commit()

                notify_ticket_assignment(ticket, user)
                create_notification(
                    user_id=ticket.submitter_id,
                    ticket_id=ticket.id,
                    title=f"Escalated Ticket #{ticket.id} Accepted",
                    message=f"Your escalated ticket has been accepted by admin {user.full_name}",
                    notification_type='escalation_accepted'
                )
                db.session.commit()
                flash('You accepted the escalated ticket.', 'success')
            else:
                flash('You are not authorized to accept this escalated ticket.', 'danger')

        return redirect(url_for('ticket_detail', ticket_id=ticket.id))

    pending_requests = []
    if user.id == ticket.assigned_to_id:
        pending_requests = TicketReassignmentRequest.query.filter_by(ticket_id=ticket.id, status='Pending').all()

    reassignment_request = TicketReassignmentRequest.query.filter_by(
        ticket_id=ticket.id,
        requested_by_id=user.id
    ).order_by(TicketReassignmentRequest.created_at.desc()).first()

    pending_suggestion_for_me = TicketAssignmentSuggestion.query.filter_by(
        ticket_id=ticket.id, target_user_id=user.id, status='Pending'
    ).first()
    it_team_members = []
    if ticket.assigned_to_id is None and user.role in ['it_staff', 'admin']:
        it_team_members = User.query.filter(
            User.role.in_(IT_TEAM_ROLES), User.id != user.id
        ).order_by(User.full_name).all()

    return render_template(
        'ticket_detail.html',
        ticket=ticket,
        user=user,
        comments=ticket.comments,
        pending_requests=pending_requests,
        reassignment_request=reassignment_request,
        pending_suggestion_for_me=pending_suggestion_for_me,
        it_team_members=it_team_members
    )


@app.route('/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if current_user.role != 'admin':
        abort(403)

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        full_name = request.form['full_name'].strip()
        email = request.form['email'].strip()
        role = request.form['role'].strip()
        room = request.form['room'].strip()

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or email already exists', 'danger')
            return redirect(url_for('create_user'))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(
            username=username,
            password_hash=hashed_pw,
            full_name=full_name,
            email=email,
            role=role,
            room=room,
            auth_source="local"
        )
        db.session.add(new_user)
        db.session.commit()
        flash('User created successfully.', 'success')
        return redirect(url_for('manage_users'))

    return render_template('create_user.html')


@app.route('/manage_users')
@login_required
def manage_users():
    if current_user.role not in ['admin', 'it_staff']:
        abort(403)
    users = User.query.order_by(User.id.asc()).all()
    return render_template('manage_users.html', users=users, user=current_user)


@app.route('/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role not in ['admin', 'it_staff']:
        abort(403)

    user_obj = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user_obj.full_name = request.form['full_name'].strip()
        user_obj.email = request.form['email'].strip()
        user_obj.role = request.form['role'].strip()
        user_obj.room = request.form['room'].strip()

        new_password = request.form.get('password', '').strip()
        if new_password:
            user_obj.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user_obj.auth_source = "local"

        db.session.commit()
        flash('User updated successfully.', 'success')
        return redirect(url_for('manage_users'))

    return render_template('edit_user.html', user=user_obj)


@app.route('/user/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role not in ['admin', 'it_staff']:
        abort(403)

    user_obj = User.query.get_or_404(user_id)

    if user_obj.id == current_user.id:
        flash("You cannot delete your own account.", "warning")
        return redirect(url_for('manage_users'))

    if user_obj.submitted_tickets or user_obj.assigned_tickets:
        flash("Cannot delete user with assigned or submitted tickets.", "danger")
        return redirect(url_for('manage_users'))

    db.session.delete(user_obj)
    db.session.commit()
    flash(f"User '{user_obj.username}' deleted successfully.", "success")
    return redirect(url_for('manage_users'))


# -----------------------------
# Assets
# -----------------------------
ASSET_TYPE_SUGGESTIONS = ['TV', 'PC', 'Laptop', 'Monitor', 'Printer', 'Scanner', 'Router', 'Switch', 'UPS', 'Phone']
ASSET_STATUSES = ['Working', 'Broken', 'Repaired']


@app.route('/assets')
@login_required
def assets():
    if current_user.role not in ['admin', 'it_staff', 'manager', 'supervisor']:
        abort(403)

    search_query = request.args.get('search', '').strip()
    type_filter = request.args.get('type', '')
    status_filter = request.args.get('status', '')
    zone_filter = request.args.get('zone', '')

    assets_query = Asset.query

    if search_query:
        like_pattern = f"%{search_query}%"
        assets_query = assets_query.filter(db.or_(
            Asset.serial_number.ilike(like_pattern),
            Asset.label_name.ilike(like_pattern),
            Asset.model.ilike(like_pattern),
            Asset.manufacturer.ilike(like_pattern),
        ))

    if type_filter:
        assets_query = assets_query.filter_by(asset_type=type_filter)
    if status_filter:
        assets_query = assets_query.filter_by(status=status_filter)
    if zone_filter:
        assets_query = assets_query.filter_by(zone=zone_filter)

    page = request.args.get('page', 1, type=int)
    per_page = 10
    pagination = assets_query.order_by(Asset.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    zones = [z[0] for z in db.session.query(Asset.zone).filter(
        Asset.zone.isnot(None), Asset.zone != ''
    ).distinct().all()]
    asset_types_in_use = [t[0] for t in db.session.query(Asset.asset_type).distinct().all()]

    unread_notifications_count = Notification.query.filter_by(
        user_id=current_user.id, is_read=False
    ).count()

    return render_template(
        'assets.html',
        assets=pagination.items,
        pagination=pagination,
        user=current_user,
        zones=sorted(zones),
        asset_types_in_use=sorted(asset_types_in_use),
        asset_statuses=ASSET_STATUSES,
        unread_notifications_count=unread_notifications_count
    )


@app.route('/assets/add', methods=['GET', 'POST'])
@login_required
def add_asset():
    if current_user.role not in ['admin', 'it_staff']:
        abort(403)

    if request.method == 'POST':
        asset_type = request.form.get('asset_type', '').strip()
        serial_number = request.form.get('serial_number', '').strip()
        status = request.form.get('status', 'Working')

        if not asset_type or not serial_number:
            flash('Asset type and serial number are required.', 'danger')
            return redirect(url_for('add_asset'))

        if status not in ASSET_STATUSES:
            status = 'Working'

        if Asset.query.filter_by(serial_number=serial_number).first():
            flash('An asset with this serial number already exists.', 'danger')
            return redirect(url_for('add_asset'))

        asset = Asset(
            asset_type=asset_type,
            label_name=request.form.get('label_name', '').strip() or None,
            serial_number=serial_number,
            zone=request.form.get('zone', '').strip() or None,
            office=request.form.get('office', '').strip() or None,
            table_number=request.form.get('table_number', '').strip() or None,
            mac_address=request.form.get('mac_address', '').strip() or None,
            cpu=request.form.get('cpu', '').strip() or None,
            ram=request.form.get('ram', '').strip() or None,
            model=request.form.get('model', '').strip() or None,
            manufacturer=request.form.get('manufacturer', '').strip() or None,
            product_number=request.form.get('product_number', '').strip() or None,
            status=status,
            added_by_id=current_user.id
        )
        db.session.add(asset)
        db.session.commit()
        flash('Asset added successfully.', 'success')
        return redirect(url_for('assets'))

    unread_notifications_count = Notification.query.filter_by(
        user_id=current_user.id, is_read=False
    ).count()

    return render_template(
        'add_asset.html',
        user=current_user,
        asset_type_suggestions=ASSET_TYPE_SUGGESTIONS,
        asset_statuses=ASSET_STATUSES,
        unread_notifications_count=unread_notifications_count
    )


@app.route('/assets/<int:asset_id>/view')
def view_asset(asset_id):
    # Deliberately public (no @login_required): this is what the printed/QR
    # asset label links to, so scanning it with a phone's stock camera app
    # must show the details directly instead of bouncing through a login wall.
    asset = Asset.query.get_or_404(asset_id)

    can_edit = current_user.is_authenticated and current_user.role in ['admin', 'it_staff']

    return render_template(
        'view_asset.html',
        asset=asset,
        can_edit=can_edit
    )


@app.route('/assets/by-serial/<serial>')
def asset_by_serial(serial):
    # Lets the in-app QR scanner (which now decodes plain asset details, not a
    # URL) find the matching asset by serial number and jump to its page.
    asset = Asset.query.filter_by(serial_number=serial).first_or_404()
    return redirect(url_for('view_asset', asset_id=asset.id))


@app.route('/assets/<int:asset_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_asset(asset_id):
    if current_user.role not in ['admin', 'it_staff']:
        abort(403)

    asset = Asset.query.get_or_404(asset_id)

    if request.method == 'POST':
        asset_type = request.form.get('asset_type', '').strip()
        serial_number = request.form.get('serial_number', '').strip()
        status = request.form.get('status', 'Working')

        if not asset_type or not serial_number:
            flash('Asset type and serial number are required.', 'danger')
            return redirect(url_for('edit_asset', asset_id=asset.id))

        if status not in ASSET_STATUSES:
            status = 'Working'

        existing = Asset.query.filter_by(serial_number=serial_number).first()
        if existing and existing.id != asset.id:
            flash('Another asset already uses this serial number.', 'danger')
            return redirect(url_for('edit_asset', asset_id=asset.id))

        asset.asset_type = asset_type
        asset.label_name = request.form.get('label_name', '').strip() or None
        asset.serial_number = serial_number
        asset.zone = request.form.get('zone', '').strip() or None
        asset.office = request.form.get('office', '').strip() or None
        asset.table_number = request.form.get('table_number', '').strip() or None
        asset.mac_address = request.form.get('mac_address', '').strip() or None
        asset.cpu = request.form.get('cpu', '').strip() or None
        asset.ram = request.form.get('ram', '').strip() or None
        asset.model = request.form.get('model', '').strip() or None
        asset.manufacturer = request.form.get('manufacturer', '').strip() or None
        asset.product_number = request.form.get('product_number', '').strip() or None
        asset.status = status

        db.session.commit()
        flash('Asset updated successfully.', 'success')
        return redirect(url_for('assets'))

    unread_notifications_count = Notification.query.filter_by(
        user_id=current_user.id, is_read=False
    ).count()

    return render_template(
        'edit_asset.html',
        asset=asset,
        user=current_user,
        asset_type_suggestions=ASSET_TYPE_SUGGESTIONS,
        asset_statuses=ASSET_STATUSES,
        unread_notifications_count=unread_notifications_count
    )


@app.route('/assets/<int:asset_id>/delete', methods=['POST'])
@login_required
def delete_asset(asset_id):
    if current_user.role not in ['admin', 'it_staff']:
        abort(403)

    asset = Asset.query.get_or_404(asset_id)
    db.session.delete(asset)
    db.session.commit()
    flash(f"Asset '{asset.serial_number}' deleted successfully.", "success")
    return redirect(url_for('assets'))


ASSET_CSV_COLUMNS = ['asset_type', 'label_name', 'serial_number', 'manufacturer', 'model', 'product_number', 'zone']


@app.route('/assets/export_csv')
@login_required
def export_assets_csv():
    if current_user.role not in ['admin', 'it_staff', 'manager', 'supervisor']:
        abort(403)

    assets_list = Asset.query.order_by(Asset.asset_type.asc(), Asset.serial_number.asc()).all()

    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(ASSET_CSV_COLUMNS)
    for a in assets_list:
        writer.writerow([
            a.asset_type, a.label_name or '', a.serial_number,
            a.manufacturer or '', a.model or '', a.product_number or '', a.zone or ''
        ])

    output = si.getvalue()
    si.close()

    return Response(output, mimetype='text/csv',
                     headers={'Content-Disposition': 'attachment; filename=assets_export.csv'})


@app.route('/assets/import_template')
@login_required
def assets_import_template():
    if current_user.role not in ['admin', 'it_staff']:
        abort(403)

    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(ASSET_CSV_COLUMNS)
    writer.writerow(['Laptop', 'IT-LAP-001', 'SN123456', 'Dell', 'Latitude 5420', 'PN-9988', 'Zone A'])
    writer.writerow(['Printer', 'IT-PRN-002', 'SN654321', 'HP', 'LaserJet Pro M404', 'PN-1122', 'Zone B'])

    output = si.getvalue()
    si.close()

    return Response(output, mimetype='text/csv',
                     headers={'Content-Disposition': 'attachment; filename=assets_import_template.csv'})


@app.route('/assets/import_csv', methods=['POST'])
@login_required
def import_assets_csv():
    if current_user.role not in ['admin', 'it_staff']:
        abort(403)

    file = request.files.get('csv_file')
    if not file or file.filename == '':
        flash('Please choose a CSV file to import.', 'danger')
        return redirect(url_for('assets'))

    if not file.filename.lower().endswith('.csv'):
        flash('Only .csv files are supported.', 'danger')
        return redirect(url_for('assets'))

    try:
        stream = StringIO(file.stream.read().decode('utf-8-sig'))
    except UnicodeDecodeError:
        flash('Could not read the file. Please save it as UTF-8 CSV and try again.', 'danger')
        return redirect(url_for('assets'))

    reader = csv.DictReader(stream)

    if not reader.fieldnames or not {'asset_type', 'serial_number'}.issubset(set(reader.fieldnames)):
        flash('The CSV must include at least "asset_type" and "serial_number" columns. Download the template to see the expected format.', 'danger')
        return redirect(url_for('assets'))

    added = 0
    skipped = 0
    errors = []

    for i, row in enumerate(reader, start=2):  # row 1 is the header
        asset_type = (row.get('asset_type') or '').strip()
        serial_number = (row.get('serial_number') or '').strip()

        if not asset_type or not serial_number:
            skipped += 1
            errors.append(f'Row {i}: missing asset type or serial number')
            continue

        if Asset.query.filter_by(serial_number=serial_number).first():
            skipped += 1
            errors.append(f'Row {i}: serial number "{serial_number}" already exists')
            continue

        asset = Asset(
            asset_type=asset_type,
            label_name=(row.get('label_name') or '').strip() or None,
            serial_number=serial_number,
            manufacturer=(row.get('manufacturer') or '').strip() or None,
            model=(row.get('model') or '').strip() or None,
            product_number=(row.get('product_number') or '').strip() or None,
            zone=(row.get('zone') or '').strip() or None,
            status='Working',
            added_by_id=current_user.id
        )
        db.session.add(asset)
        added += 1

    db.session.commit()

    if added:
        flash(f'{added} asset(s) imported successfully.', 'success')
    if skipped:
        summary = '; '.join(errors[:5])
        if len(errors) > 5:
            summary += f' ... and {len(errors) - 5} more'
        flash(f'{skipped} row(s) skipped. {summary}', 'warning')
    if not added and not skipped:
        flash('No rows found in the CSV file.', 'warning')

    return redirect(url_for('assets'))


@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    if current_user.role not in ['admin', 'it_staff', 'manager', 'supervisor']:
        abort(403)

    query = Ticket.query

    if request.method == 'POST':
        status = request.form.get('status')
        room = request.form.get('room')
        date_from = request.form.get('date_from')
        date_to = request.form.get('date_to')

        if status:
            query = query.filter_by(status=status)
        if room:
            query = query.filter_by(room=room)

        if date_from and date_to:
            try:
                start = datetime.strptime(date_from, '%Y-%m-%d')
                end = datetime.strptime(date_to, '%Y-%m-%d')
                start_naive = RIYADH_TZ.localize(start.replace(hour=0, minute=0, second=0)).replace(tzinfo=None)
                end_naive = RIYADH_TZ.localize(end.replace(hour=23, minute=59, second=59)).replace(tzinfo=None)
                query = query.filter(Ticket.created_at.between(start_naive, end_naive))
            except ValueError:
                flash('Invalid date format.', 'danger')

    tickets = query.order_by(Ticket.created_at.desc()).all()
    return render_template('report.html', tickets=tickets, user=current_user)


@app.route('/export_csv')
@login_required
def export_csv():
    if current_user.role not in ['admin', 'it_staff', 'manager', 'supervisor']:
        abort(403)

    tickets = Ticket.query.order_by(Ticket.created_at.desc()).all()

    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['ID', 'Submitter', 'Room', 'Category', 'Status', 'Assigned To', 'Created At (Riyadh)', 'Updated At (Riyadh)'])

    for t in tickets:
        writer.writerow([
            t.id,
            t.submitter.full_name,
            t.room,
            t.category,
            t.status,
            t.assigned_to.full_name if t.assigned_to else '',
            format_riyadh_datetime(t.created_at),
            format_riyadh_datetime(t.updated_at)
        ])

    output = si.getvalue()
    si.close()

    return Response(output, mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=ticket_report_riyadh.csv'})


# -----------------------------
# IT Team: roster + chat
# -----------------------------
@app.route('/team')
@login_required
def team():
    if current_user.role not in ['it_staff', 'admin', 'it_admin']:
        abort(403)
    members = User.query.filter(User.role.in_(IT_TEAM_ROLES)).order_by(User.full_name).all()
    cutoff = get_riyadh_time_naive() - PRESENCE_ONLINE_WINDOW
    online_ids = {
        p.user_id for p in UserPresence.query.filter(UserPresence.last_seen_at >= cutoff).all()
    }

    # Chat partners outside the regular roster (e.g. it_admin, who isn't a
    # roster/assignee member) still need to be reachable once a thread exists.
    member_ids = {m.id for m in members}
    partner_ids = set()
    for m in Message.query.filter(
        db.or_(Message.sender_id == current_user.id, Message.recipient_id == current_user.id),
        Message.recipient_id.isnot(None)
    ).all():
        other_id = m.recipient_id if m.sender_id == current_user.id else m.sender_id
        if other_id != current_user.id:
            partner_ids.add(other_id)
    extra_partner_ids = partner_ids - member_ids
    extra_partners = User.query.filter(User.id.in_(extra_partner_ids)).order_by(User.full_name).all() if extra_partner_ids else []

    return render_template(
        'team.html', members=members, online_ids=online_ids,
        extra_partners=extra_partners, user=current_user
    )


@app.route('/chat/<int:user_id>', methods=['GET', 'POST'])
@login_required
def chat_thread(user_id):
    if current_user.role not in IT_CHAT_ROLES:
        abort(403)
    other = User.query.get_or_404(user_id)
    if other.role not in IT_CHAT_ROLES or other.id == current_user.id:
        abort(404)

    if request.method == 'POST':
        body = request.form.get('body', '').strip()
        if body:
            db.session.add(Message(sender_id=current_user.id, recipient_id=other.id, body=body))
            db.session.commit()
        return redirect(url_for('chat_thread', user_id=other.id))

    Message.query.filter_by(sender_id=other.id, recipient_id=current_user.id, is_read=False) \
        .update({'is_read': True})
    db.session.commit()

    messages = Message.query.filter(
        db.or_(
            db.and_(Message.sender_id == current_user.id, Message.recipient_id == other.id),
            db.and_(Message.sender_id == other.id, Message.recipient_id == current_user.id)
        )
    ).order_by(Message.created_at.asc()).all()

    return render_template('chat_thread.html', other=other, messages=messages, user=current_user)


@app.route('/api/chat/<int:user_id>/messages')
@login_required
def api_chat_messages(user_id):
    if current_user.role not in IT_CHAT_ROLES:
        abort(403)
    other = User.query.get_or_404(user_id)
    since_id = request.args.get('since_id', 0, type=int)

    new_messages = Message.query.filter(
        Message.id > since_id,
        db.or_(
            db.and_(Message.sender_id == current_user.id, Message.recipient_id == other.id),
            db.and_(Message.sender_id == other.id, Message.recipient_id == current_user.id)
        )
    ).order_by(Message.id.asc()).all()

    unread_ids = [m.id for m in new_messages if m.sender_id == other.id and not m.is_read]
    if unread_ids:
        Message.query.filter(Message.id.in_(unread_ids)).update({'is_read': True}, synchronize_session=False)
        db.session.commit()

    return jsonify([{
        'id': m.id,
        'is_mine': m.sender_id == current_user.id,
        'body': m.body,
        'created_at': format_riyadh_datetime(m.created_at)
    } for m in new_messages])


@app.route('/team-channel', methods=['GET', 'POST'])
@login_required
def team_channel():
    if current_user.role not in ['it_staff', 'admin', 'it_admin']:
        abort(403)

    if request.method == 'POST':
        if current_user.role not in IT_CHAT_ROLES:
            abort(403)
        body = request.form.get('body', '').strip()
        if body:
            db.session.add(Message(sender_id=current_user.id, recipient_id=None, body=body))
            db.session.commit()
        return redirect(url_for('team_channel'))

    messages = Message.query.filter_by(recipient_id=None).order_by(Message.created_at.asc()).all()

    marker = ChannelReadMarker.query.filter_by(user_id=current_user.id).first()
    if not marker:
        marker = ChannelReadMarker(user_id=current_user.id)
        db.session.add(marker)
    marker.last_seen_at = get_riyadh_time_naive()
    db.session.commit()

    return render_template('team_channel.html', messages=messages, user=current_user)


@app.route('/api/team-channel/messages')
@login_required
def api_team_channel_messages():
    if current_user.role not in ['it_staff', 'admin', 'it_admin']:
        abort(403)
    since_id = request.args.get('since_id', 0, type=int)
    new_messages = Message.query.filter(
        Message.recipient_id.is_(None), Message.id > since_id
    ).order_by(Message.id.asc()).all()

    marker = ChannelReadMarker.query.filter_by(user_id=current_user.id).first()
    if not marker:
        marker = ChannelReadMarker(user_id=current_user.id)
        db.session.add(marker)
    marker.last_seen_at = get_riyadh_time_naive()
    db.session.commit()

    return jsonify([{
        'id': m.id,
        'sender_name': m.sender.full_name if m.sender else 'مستخدم',
        'is_mine': m.sender_id == current_user.id,
        'body': m.body,
        'created_at': format_riyadh_datetime(m.created_at)
    } for m in new_messages])


@app.route('/api/chat/unread_count')
@login_required
def api_chat_unread_count():
    if current_user.role not in IT_CHAT_ROLES:
        return jsonify({'count': 0})

    dm_count = Message.query.filter_by(recipient_id=current_user.id, is_read=False).count()

    marker = ChannelReadMarker.query.filter_by(user_id=current_user.id).first()
    channel_query = Message.query.filter(
        Message.recipient_id.is_(None),
        Message.sender_id != current_user.id
    )
    if marker:
        channel_query = channel_query.filter(Message.created_at > marker.last_seen_at)
    channel_count = channel_query.count()

    return jsonify({'count': dm_count + channel_count})


PRESENCE_ONLINE_WINDOW = timedelta(minutes=2)


@app.route('/api/presence/heartbeat', methods=['POST'])
@login_required
def api_presence_heartbeat():
    marker = UserPresence.query.filter_by(user_id=current_user.id).first()
    if not marker:
        marker = UserPresence(user_id=current_user.id)
        db.session.add(marker)
    marker.last_seen_at = get_riyadh_time_naive()
    db.session.commit()
    return jsonify({'ok': True})


@app.route('/api/team/presence')
@login_required
def api_team_presence():
    if current_user.role not in ['it_staff', 'admin', 'it_admin']:
        abort(403)
    cutoff = get_riyadh_time_naive() - PRESENCE_ONLINE_WINDOW
    online_ids = {
        p.user_id for p in UserPresence.query.filter(UserPresence.last_seen_at >= cutoff).all()
    }
    members = User.query.filter(User.role.in_(IT_TEAM_ROLES)).all()
    return jsonify({str(m.id): (m.id in online_ids) for m in members})


# -----------------------------
# IT Team: tasks (assignment, delegation, escalation)
# -----------------------------
@app.route('/tasks')
@login_required
def tasks_mine():
    if current_user.role not in IT_TEAM_ROLES:
        abort(403)
    assignments = TaskAssignment.query.filter_by(assignee_id=current_user.id) \
        .order_by(TaskAssignment.created_at.desc()).all()
    return render_template('tasks_mine.html', assignments=assignments, user=current_user)


@app.route('/tasks/created')
@login_required
def tasks_created():
    if current_user.role not in ['it_admin', 'admin']:
        abort(403)
    created_tasks = Task.query.filter_by(created_by_id=current_user.id) \
        .order_by(Task.created_at.desc()).all()
    return render_template('tasks_created.html', tasks=created_tasks, user=current_user)


@app.route('/tasks/team')
@login_required
def tasks_team():
    if current_user.role not in ['it_staff', 'admin', 'it_admin']:
        abort(403)
    assignments = TaskAssignment.query.order_by(TaskAssignment.created_at.desc()).all()
    return render_template('tasks_team.html', assignments=assignments, user=current_user)


@app.route('/tasks/new', methods=['GET', 'POST'])
@login_required
def task_new():
    if current_user.role not in ['it_admin', 'admin', 'it_staff']:
        abort(403)

    # it_staff can only ever create a task for themselves - never for a
    # teammate or the whole team - enforced server-side, not just hidden in the UI.
    self_service_only = current_user.role == 'it_staff'

    it_members = User.query.filter(User.role.in_(IT_TEAM_ROLES)).order_by(User.full_name).all()

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        assign_to = str(current_user.id) if self_service_only else request.form.get('assign_to', '')

        if not title or not description:
            flash('العنوان والوصف مطلوبان.', 'danger')
            return redirect(url_for('task_new'))

        is_team_wide = (not self_service_only) and assign_to == 'team'
        task = Task(created_by_id=current_user.id, title=title, description=description, is_team_wide=is_team_wide)
        db.session.add(task)
        db.session.flush()

        if is_team_wide:
            for member in it_members:
                db.session.add(TaskAssignment(task_id=task.id, assignee_id=member.id))
        else:
            try:
                assignee_id = int(assign_to)
            except (TypeError, ValueError):
                db.session.rollback()
                flash('الرجاء اختيار موظف أو الفريق بالكامل.', 'danger')
                return redirect(url_for('task_new'))
            assignee = User.query.get(assignee_id)
            if not assignee or assignee.role not in IT_TEAM_ROLES:
                db.session.rollback()
                flash('الموظف المحدد غير صالح.', 'danger')
                return redirect(url_for('task_new'))
            db.session.add(TaskAssignment(task_id=task.id, assignee_id=assignee.id))

        db.session.commit()
        flash('تم إنشاء المهمة بنجاح.', 'success')
        return redirect(url_for('tasks_created') if current_user.role in ['it_admin', 'admin'] else url_for('tasks_mine'))

    return render_template(
        'task_new.html', it_members=it_members, self_service_only=self_service_only, user=current_user
    )


@app.route('/tasks/<int:task_id>')
@login_required
def task_detail(task_id):
    task = Task.query.get_or_404(task_id)
    my_assignment = TaskAssignment.query.filter_by(task_id=task.id, assignee_id=current_user.id).first()
    is_creator = task.created_by_id == current_user.id

    # A delegation target doesn't have their own TaskAssignment row on this task yet
    # (that only exists once they accept), so they need a separate way in.
    pending_delegations_for_me = TaskDelegationRequest.query.join(TaskAssignment).filter(
        TaskAssignment.task_id == task.id,
        TaskDelegationRequest.target_user_id == current_user.id,
        TaskDelegationRequest.status == 'Pending'
    ).all()

    if not is_creator and not my_assignment and not pending_delegations_for_me and current_user.role != 'admin':
        abort(403)

    it_members = None
    if my_assignment:
        it_members = User.query.filter(User.role.in_(IT_TEAM_ROLES), User.id != current_user.id) \
            .order_by(User.full_name).all()

    return render_template(
        'task_detail.html',
        task=task,
        is_creator=is_creator,
        my_assignment=my_assignment,
        pending_delegations_for_me=pending_delegations_for_me,
        it_members=it_members,
        user=current_user
    )


@app.route('/tasks/<int:assignment_id>/action', methods=['POST'])
@login_required
def task_assignment_action(assignment_id):
    assignment = TaskAssignment.query.get_or_404(assignment_id)
    task = assignment.task
    action = request.form.get('action')

    if action == 'submit_completion':
        if assignment.assignee_id != current_user.id:
            abort(403)
        completion_text = request.form.get('completion_text', '').strip()
        if not completion_text:
            flash('الرجاء وصف ما تم إنجازه قبل إغلاق المهمة.', 'danger')
            return redirect(url_for('task_detail', task_id=task.id))

        assignment.status = 'Done'
        db.session.add(TaskComment(
            task_assignment_id=assignment.id,
            user_id=current_user.id,
            comment_type='completion',
            body=completion_text
        ))

        file = request.files.get('file')
        if file and file.filename:
            if not allowed_file(file.filename):
                flash('نوع الملف غير مسموح به.', 'warning')
            else:
                task_folder = os.path.join(app.config['UPLOAD_FOLDER'], f'task_{assignment.id}')
                os.makedirs(task_folder, exist_ok=True)
                filename = secure_filename(file.filename)
                unique_filename = f"{int(datetime.now().timestamp())}_{filename}"
                file.save(os.path.join(task_folder, unique_filename))
                db.session.add(TaskAttachment(
                    task_assignment_id=assignment.id,
                    uploaded_by_id=current_user.id,
                    filename=f'task_{assignment.id}/{unique_filename}'
                ))

        db.session.commit()
        flash('تم إرسال إثبات إنجاز المهمة ووضع علامة عليها كمكتملة.', 'success')

    elif action == 'ask_question':
        if assignment.assignee_id != current_user.id:
            abort(403)
        question_text = request.form.get('question_text', '').strip()
        if not question_text:
            flash('الرجاء كتابة سؤالك.', 'danger')
            return redirect(url_for('task_detail', task_id=task.id))
        db.session.add(TaskComment(
            task_assignment_id=assignment.id,
            user_id=current_user.id,
            comment_type='question',
            body=question_text
        ))
        db.session.commit()
        flash('تم إرسال سؤالك.', 'success')

    elif action == 'answer_question':
        if not (current_user.id == task.created_by_id or current_user.role == 'admin'):
            abort(403)
        answer_text = request.form.get('answer_text', '').strip()
        if not answer_text:
            flash('الرجاء كتابة الرد.', 'danger')
            return redirect(url_for('task_detail', task_id=task.id))
        db.session.add(TaskComment(
            task_assignment_id=assignment.id,
            user_id=current_user.id,
            comment_type='answer',
            body=answer_text
        ))
        db.session.commit()
        flash('تم إرسال الرد.', 'success')

    elif action == 'request_delegation':
        if assignment.assignee_id != current_user.id:
            abort(403)
        target_user_id = request.form.get('target_user_id', type=int)
        reason = request.form.get('reason', '').strip()
        target = User.query.get(target_user_id) if target_user_id else None
        if not target or target.role not in IT_TEAM_ROLES or target.id == current_user.id:
            flash('الرجاء اختيار زميل صالح لتحويل المهمة إليه.', 'danger')
            return redirect(url_for('task_detail', task_id=task.id))
        if not reason:
            flash('الرجاء كتابة سبب التحويل.', 'danger')
            return redirect(url_for('task_detail', task_id=task.id))
        existing = TaskDelegationRequest.query.filter_by(task_assignment_id=assignment.id, status='Pending').first()
        if existing:
            flash('يوجد طلب تحويل قيد الانتظار بالفعل لهذه المهمة.', 'warning')
            return redirect(url_for('task_detail', task_id=task.id))
        db.session.add(TaskDelegationRequest(
            task_assignment_id=assignment.id,
            requested_by_id=current_user.id,
            target_user_id=target.id,
            reason=reason
        ))
        db.session.commit()
        flash('تم إرسال طلب التحويل.', 'success')

    elif action == 'handle_delegation':
        request_id = request.form.get('request_id', type=int)
        decision = request.form.get('decision')
        deleg = TaskDelegationRequest.query.get_or_404(request_id)
        if deleg.target_user_id != current_user.id or deleg.status != 'Pending':
            abort(403)
        if decision == 'accept':
            deleg.status = 'Accepted'
            assignment.assignee_id = current_user.id
            assignment.status = 'In Progress'
            flash('تم قبول المهمة.', 'success')
        elif decision == 'reject':
            deleg.status = 'Rejected'
            flash('تم رفض طلب التحويل.', 'info')
        db.session.commit()

    elif action == 'escalate_task':
        if assignment.assignee_id != current_user.id:
            abort(403)
        assignment.status = 'Escalated'
        db.session.commit()
        flash('تم تصعيد المهمة إلى المدير.', 'success')

    elif action == 'accept_escalated_task':
        if not (current_user.id == task.created_by_id or current_user.role == 'admin'):
            abort(403)
        if assignment.status != 'Escalated':
            flash('هذه المهمة ليست في حالة تصعيد.', 'warning')
            return redirect(url_for('task_detail', task_id=task.id))
        assignment.status = 'In Progress'
        db.session.commit()
        flash('تم استلام المهمة المصعدة.', 'success')

    else:
        abort(400)

    return redirect(url_for('task_detail', task_id=task.id))


@app.route('/api/tasks/badge_count')
@login_required
def api_tasks_badge_count():
    count = 0
    if current_user.role in IT_TEAM_ROLES:
        count += TaskAssignment.query.filter_by(assignee_id=current_user.id) \
            .filter(TaskAssignment.status.in_(['Open', 'Escalated'])).count()
        count += TaskDelegationRequest.query.filter_by(target_user_id=current_user.id, status='Pending').count()
    if current_user.role in ['it_admin', 'admin']:
        count += TaskAssignment.query.join(Task).filter(
            Task.created_by_id == current_user.id,
            TaskAssignment.status == 'Escalated'
        ).count()
    return jsonify({'count': count})


@app.route('/uploads/<path:filename>')
def uploads(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/debug/users')
@login_required
def debug_users():
    if current_user.role != 'admin':
        abort(403)
    users = User.query.order_by(User.id.asc()).all()
    return jsonify([{
        "id": u.id,
        "username": u.username,
        "full_name": u.full_name,
        "email": u.email,
        "role": u.role,
        "room": u.room,
        "auth_source": u.auth_source
    } for u in users])


def create_default_admin():
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        temp_password = secrets.token_urlsafe(9)
        pw_hash = bcrypt.generate_password_hash(temp_password).decode('utf-8')
        admin = User(
            username='admin',
            password_hash=pw_hash,
            full_name='Administrator',
            email='admin@gmail.com',
            role='admin',
            room='HQ',
            auth_source='local'
        )
        db.session.add(admin)
        db.session.commit()
        print("=" * 60)
        print(f"Default admin created: username=admin, password={temp_password}")
        print("Log in and change this password from the profile page.")
        print("=" * 60)


# Runs on import, not just under `python app.py` - a WSGI server like gunicorn
# imports this module directly and never hits the __main__ guard below, so
# table creation/default-admin setup must happen unconditionally at import time.
with app.app_context():
    db.create_all()
    create_default_admin()


if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', '1') == '1'
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=debug_mode)