import os
from datetime import datetime
import io
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, abort, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()

from sqlalchemy import func, text
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas as pdf_canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'log', 'zip', 'rar', 'doc', 'docx'])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    'postgresql://postgres:postgres@localhost:5432/crm_db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads'))
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_CONTENT_LENGTH', 10 * 1024 * 1024))  # 10MB

SUPPORT_CODE = os.environ.get('SUPPORT_CODE', 'SUPPORT123')  # секрет для регистрации поддержки

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Человекочитаемые метки статусов (русские значения)
STATUS_LABELS = {
    'open': 'Открыт',
    'in_progress': 'В работе',
    'resolved': 'Выполнен',
}


@app.template_filter('status_label')
def status_label_filter(status):
    # Возвращает русскую метку статуса для шаблонов
    return STATUS_LABELS.get(status, status)


def get_status_label(status):
    # Возвращает русскую метку статуса для внутреннего использования (PDF и т.п.)
    return STATUS_LABELS.get(status, status)


# Метки приоритетов (русские значения для отображения)
PRIORITY_LABELS = {
    'low': 'Низкий',
    'medium': 'Средний',
    'high': 'Высокий',
}


@app.template_filter('priority_label')
def priority_label_filter(priority):
    # Возвращает русскую метку приоритета для шаблонов
    return PRIORITY_LABELS.get(priority, priority)


def get_priority_label(priority):
    # Возвращает русскую метку приоритета для внутреннего использования (PDF и т.п.)
    return PRIORITY_LABELS.get(priority, priority)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(200), nullable=False, unique=True)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')  # роль пользователя: 'user', 'support', 'manager', 'admin'
    # поля профиля пользователя
    company_name = db.Column(db.String(255), nullable=True)
    address = db.Column(db.String(500), nullable=True)
    first_name = db.Column(db.String(150), nullable=True)
    last_name = db.Column(db.String(150), nullable=True)
    phone = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    tickets_created = db.relationship('Ticket', backref='creator', foreign_keys='Ticket.creator_id', lazy='dynamic')
    tickets_assigned = db.relationship('Ticket', backref='assignee', foreign_keys='Ticket.assignee_id', lazy='dynamic')
    comments = db.relationship('TicketComment', backref='author', lazy='dynamic')
    attachments = db.relationship('Attachment', backref='uploader', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), nullable=False, default='open')  # возможные значения: open, in_progress, resolved
    priority = db.Column(db.String(20), nullable=False, default='medium')  # приоритет: low, medium, high (хранится как ключ)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    comments = db.relationship('TicketComment', backref='ticket', lazy='dynamic', cascade="all, delete-orphan")
    attachments = db.relationship('Attachment', backref='ticket', lazy='dynamic', cascade="all, delete-orphan")


class TicketComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    attachment = db.relationship('Attachment', backref='comment', uselist=False)


class Attachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300), nullable=False)       # имя файла в хранилище (stored filename)
    original_name = db.Column(db.String(300), nullable=False)  # оригинальное имя загруженного файла
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=True)
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comment_id = db.Column(db.Integer, db.ForeignKey('ticket_comment.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def create_tables():
    # Проверяем, какие таблицы уже есть в базе через инспектор SQLAlchemy
    missing = []
    try:
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        existing_tables = set(inspector.get_table_names())
        required_tables = {'user', 'ticket', 'ticket_comment', 'attachment'}
        missing = list(required_tables - existing_tables)
    except Exception as e:
        app.logger.exception('DB inspection failed: %s', e)
        # Если инспекция упала, попытаемся всё равно создать таблицы
        missing = ['unknown']

    if missing:
        try:
            app.logger.info('Missing tables detected: %s. Creating tables...', ','.join(missing))
            db.create_all()
            app.logger.info('Tables created (if they did not exist).')
            # Убедимся, что колонки профиля существуют (используем ALTER TABLE IF NOT EXISTS при поддержке)
            try:
                stmts = [
                    "ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS company_name VARCHAR(255);",
                    "ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS address VARCHAR(500);",
                    "ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS first_name VARCHAR(150);",
                    "ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS last_name VARCHAR(150);",
                    "ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS phone VARCHAR(50);",
                ]
                for s in stmts:
                    try:
                        db.session.execute(text(s))
                    except Exception:
                        # в качестве запасного варианта попробуем выполнить через engine.execute
                        try:
                            db.engine.execute(text(s))
                        except Exception as e:
                            app.logger.debug('Could not run alter statement (%s): %s', s, e)
                db.session.commit()
            except Exception as e:
                app.logger.exception('Failed to ensure profile columns exist: %s', e)
        except Exception as e:
            app.logger.exception('Failed to create tables: %s', e)

    # Создаём пользователя admin по умолчанию, если его нет
    try:
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin_email = os.environ.get('ADMIN_EMAIL', 'admin@localhost')
            admin_password = os.environ.get('ADMIN_PASSWORD', 'admin')
            admin = User(username='admin', email=admin_email, role='admin')
            admin.set_password(admin_password)
            db.session.add(admin)
            db.session.commit()
            app.logger.info('Created default admin user "admin"')
    except Exception as e:
        app.logger.exception('Failed to ensure admin user exists: %s', e)


# Некоторые версии Flask (или альтернативные точки входа WSGI) могут не поддерживать
# декоратор `before_first_request` при импорте внутри контейнера.
# Поэтому инициализируем базу/таблицы/админа прямо сейчас в контексте приложения.
try:
    with app.app_context():
        create_tables()
except Exception as e:
    app.logger.exception('Error while initializing DB at import time: %s', e)

# Гарантируем существование колонок профиля и поля resolved_at, даже если таблицы уже были созданы
def ensure_profile_columns():
    stmts = [
        'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS company_name VARCHAR(255);',
        'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS address VARCHAR(500);',
        'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS first_name VARCHAR(150);',
        'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS last_name VARCHAR(150);',
        'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS phone VARCHAR(50);',
        'ALTER TABLE "ticket" ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMP;',
    ]
    try:
        with db.engine.begin() as conn:
            for s in stmts:
                try:
                    conn.execute(text(s))
                except Exception as e:
                    app.logger.debug('Could not run alter statement (%s): %s', s, e)
    except Exception as e:
        app.logger.exception('Failed to ensure profile columns exist: %s', e)

try:
    with app.app_context():
        ensure_profile_columns()
except Exception as e:
    app.logger.exception('Error while ensuring profile columns at import time: %s', e)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip()
        password = request.form.get('password')
        support_code = request.form.get('support_code', '').strip()

        if not username or not email or not password:
            flash('Заполните все обязательные поля.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Пользователь с таким именем или email уже существует.', 'danger')
            return redirect(url_for('register'))

        role = 'support' if support_code and support_code == SUPPORT_CODE else 'user'
        user = User(username=username, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Регистрация прошла успешно. Войдите в систему.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form.get('username_or_email').strip()
        password = request.form.get('password')
        user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email)).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Вход выполнен.', 'success')
            return redirect(url_for('dashboard'))
        flash('Неверные данные для входа.', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    # Для админа доступна отдельная страница управления пользователями
    if current_user.role == 'admin':
        return redirect(url_for('admin_users'))
    if current_user.role == 'manager':
        return redirect(url_for('manager_dashboard'))
    if current_user.role == 'support':
        return redirect(url_for('support_dashboard'))
    return redirect(url_for('user_dashboard'))


@app.route('/admin/users')
@login_required
def admin_users():
    # Только админ может попасть сюда
    if current_user.role != 'admin':
        flash('Доступ запрещён.', 'warning')
        return redirect(url_for('dashboard'))
    users = User.query.order_by(User.created_at.asc()).all()
    roles = ['user', 'support', 'manager', 'admin']
    return render_template('admin_users.html', users=users, roles=roles)


@app.route('/admin/users/<int:user_id>/role', methods=['POST'])
@login_required
def admin_set_role(user_id):
    if current_user.role != 'admin':
        flash('Доступ запрещён.', 'warning')
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')
    if new_role not in ('user', 'support', 'admin', 'manager'):
        flash('Недопустимая роль.', 'danger')
        return redirect(url_for('admin_users'))
    # Предотвращаем изменение собственной роли таким образом, чтобы заблокировать себя (простая проверка)
    if user.id == current_user.id and new_role != 'admin':
        flash('Нельзя изменить свою собственную роль.', 'warning')
        return redirect(url_for('admin_users'))
    user.role = new_role
    db.session.commit()
    flash('Роль обновлена.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def admin_edit_user_profile(user_id):
    if current_user.role != 'admin':
        flash('Доступ запрещён.', 'warning')
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        # Позволяем админу редактировать username/email с проверкой уникальности
        new_username = request.form.get('username', '').strip()
        new_email = request.form.get('email', '').strip()
        if new_username and new_username != user.username:
            if User.query.filter(User.username == new_username).first():
                flash('Имя пользователя занято.', 'danger')
                return redirect(url_for('admin_edit_user_profile', user_id=user.id))
            user.username = new_username
        if new_email and new_email != user.email:
            if User.query.filter(User.email == new_email).first():
                flash('Email уже используется.', 'danger')
                return redirect(url_for('admin_edit_user_profile', user_id=user.id))
            user.email = new_email
        user.first_name = request.form.get('first_name') or None
        user.last_name = request.form.get('last_name') or None
        user.phone = request.form.get('phone') or None
        user.company_name = request.form.get('company_name') or None
        user.address = request.form.get('address') or None
        db.session.commit()
        flash('Профиль пользователя обновлён.', 'success')
        return redirect(url_for('admin_users'))
    return render_template('profile.html', user=user, allow_credentials_edit=True)


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if current_user.role != 'admin':
        flash('Доступ запрещён.', 'warning')
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    # Не позволяем удалить самого себя
    if user.id == current_user.id:
        flash('Нельзя удалить самого себя.', 'warning')
        return redirect(url_for('admin_users'))
    try:
        # Удаляем тикеты, созданные пользователем (и их вложения/комментарии)
        tickets = Ticket.query.filter_by(creator_id=user.id).all()
        for t in tickets:
            # Удаляем вложения, привязанные к тикету
            Attachment.query.filter_by(ticket_id=t.id).delete()
            # Удаляем комментарии к тикету (и их вложения)
            TicketComment.query.filter_by(ticket_id=t.id).delete()
            db.session.delete(t)

        # Снимаем назначения с тикетов, где пользователь был исполнителем
        Ticket.query.filter(Ticket.assignee_id == user.id).update({ 'assignee_id': None })

        # Удаляем вложения и комментарии, автором которых был пользователь (если они не связаны с уже удалёнными тикетами)
        Attachment.query.filter_by(uploader_id=user.id).delete()
        TicketComment.query.filter_by(author_id=user.id).delete()

        db.session.delete(user)
        db.session.commit()
        flash('Пользователь и его созданные заявки удалены.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.exception('Ошибка при удалении пользователя: %s', e)
        flash('Ошибка при удалении пользователя. Проверьте логи.', 'danger')
    return redirect(url_for('admin_users'))


@app.route('/admin/user/<int:user_id>/password', methods=['GET', 'POST'])
@login_required
def admin_change_user_password(user_id):
    if current_user.role != 'admin':
        flash('Доступ запрещён.', 'warning')
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        password2 = request.form.get('password2', '').strip()
        if not password:
            flash('Введите новый пароль.', 'danger')
            return redirect(url_for('admin_change_user_password', user_id=user.id))
        if password != password2:
            flash('Пароли не совпадают.', 'danger')
            return redirect(url_for('admin_change_user_password', user_id=user.id))
        user.set_password(password)
        db.session.commit()
        flash('Пароль пользователя обновлён.', 'success')
        return redirect(url_for('admin_users'))
    return render_template('admin_change_password.html', user=user)


@app.route('/user')
@login_required
def user_dashboard():
    if current_user.role != 'user':
        flash('Только пользователи могут видеть эту страницу.', 'warning')
        return redirect(url_for('dashboard'))
    tickets = Ticket.query.filter_by(creator_id=current_user.id).order_by(Ticket.created_at.desc()).all()
    return render_template('user_dashboard.html', tickets=tickets)


@app.route('/manager')
@login_required
def manager_dashboard():
    if current_user.role != 'manager':
        flash('Только менеджер может видеть эту страницу.', 'warning')
        return redirect(url_for('dashboard'))
    try:
        # Статистика: количество тикетов по создателям (по пользователю) и по компаниям, а также по исполнителям
        creators_by_user = db.session.query(
            User.id, User.first_name, User.last_name, User.username, db.func.count(Ticket.id).label('cnt')
        ).join(Ticket, Ticket.creator_id == User.id).group_by(User.id, User.first_name, User.last_name, User.username).order_by(db.desc('cnt')).all()

        creators_stats = []
        for uid, first, last, username, cnt in creators_by_user:
            display = (f"{last or ''} {first or ''}".strip() or username)
            creators_stats.append((display, cnt))

        # Агрегация по названию компании
        creators_by_company = db.session.query(
            User.company_name, db.func.count(Ticket.id).label('cnt')
        ).join(Ticket, Ticket.creator_id == User.id).group_by(User.company_name).order_by(db.desc('cnt')).all()
        creators_companies = [((cn or '—'), cnt) for cn, cnt in creators_by_company]

        assignees_by_user = db.session.query(
            User.id, User.first_name, User.last_name, User.username, db.func.count(Ticket.id).label('cnt')
        ).join(Ticket, Ticket.assignee_id == User.id).group_by(User.id, User.first_name, User.last_name, User.username).order_by(db.desc('cnt')).all()
        assignees_stats = []
        for uid, first, last, username, cnt in assignees_by_user:
            display = (f"{last or ''} {first or ''}".strip() or username)
            assignees_stats.append((display, cnt))

        recent_tickets = Ticket.query.order_by(Ticket.created_at.desc()).limit(20).all()
    except Exception as e:
        app.logger.exception('Ошибка при формировании данных менеджера: %s', e)
        flash('Произошла ошибка при загрузке данных менеджера. Проверьте логи.', 'danger')
        creators_stats = []
        assignees_stats = []
        recent_tickets = []
    return render_template('manager_dashboard.html', creators_stats=creators_stats, creators_companies=creators_companies, assignees_stats=assignees_stats, recent_tickets=recent_tickets)


@app.route('/manager/tickets')
@login_required
def manager_tickets():
    if current_user.role != 'manager':
        flash('Только менеджер может видеть эту страницу.', 'warning')
        return redirect(url_for('dashboard'))
    tickets = Ticket.query.order_by(Ticket.created_at.desc()).all()
    return render_template('manager_tickets.html', tickets=tickets)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = current_user
    if request.method == 'POST':
        user.first_name = request.form.get('first_name') or None
        user.last_name = request.form.get('last_name') or None
        user.phone = request.form.get('phone') or None
        user.company_name = request.form.get('company_name') or None
        user.address = request.form.get('address') or None
        db.session.commit()
        flash('Профиль сохранён.', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=user)


@app.route('/manager/users')
@login_required
def manager_users():
    if current_user.role != 'manager':
        flash('Только менеджер может видеть эту страницу.', 'warning')
        return redirect(url_for('dashboard'))
    users = User.query.order_by(User.username.asc()).all()
    return render_template('manager_users.html', users=users)


@app.route('/manager/user/<int:user_id>/profile', methods=['GET', 'POST'])
@login_required
def manager_edit_user_profile(user_id):
    if current_user.role not in ('manager', 'admin'):
        flash('Только менеджер или админ может редактировать профиль пользователя.', 'warning')
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.first_name = request.form.get('first_name') or None
        user.last_name = request.form.get('last_name') or None
        user.phone = request.form.get('phone') or None
        user.company_name = request.form.get('company_name') or None
        user.address = request.form.get('address') or None
        db.session.commit()
        flash('Профиль пользователя обновлён.', 'success')
        return redirect(url_for('manager_users'))
    return render_template('profile.html', user=user)


@app.route('/manager/performers')
@login_required
def manager_performers():
    if current_user.role != 'manager':
        flash('Только менеджер может видеть эту страницу.', 'warning')
        return redirect(url_for('dashboard'))
    # Исполнители — пользователи с ролью 'support'
    performers = User.query.filter_by(role='support').order_by(User.username.asc()).all()
    return render_template('manager_performers.html', performers=performers)


@app.route('/manager/ticket/<int:ticket_id>/edit', methods=['GET', 'POST'])
@login_required
def manager_edit_ticket(ticket_id):
    if current_user.role != 'manager':
        flash('Только менеджер может редактировать тикеты.', 'warning')
        return redirect(url_for('dashboard'))
    t = Ticket.query.get_or_404(ticket_id)
    if request.method == 'POST':
        t.title = request.form.get('title', t.title).strip()
        t.description = request.form.get('description', t.description).strip()
        t.priority = request.form.get('priority', t.priority)
        t.status = request.form.get('status', t.status)
        assignee_id = request.form.get('assignee')
        t.assignee_id = int(assignee_id) if assignee_id and assignee_id != 'None' else None
        db.session.commit()
        flash('Тикет обновлён.', 'success')
        return redirect(url_for('manager_tickets'))
    performers = User.query.filter_by(role='support').order_by(User.username.asc()).all()
    return render_template('manager_edit_ticket.html', ticket=t, performers=performers)


@app.route('/manager/ticket/<int:ticket_id>/delete', methods=['POST'])
@login_required
def manager_delete_ticket(ticket_id):
    if current_user.role not in ('manager', 'admin'):
        flash('Недостаточно прав для удаления тикета.', 'warning')
        return redirect(url_for('dashboard'))
    t = Ticket.query.get_or_404(ticket_id)
    try:
        # Удаляем вложения тикета
        Attachment.query.filter_by(ticket_id=t.id).delete()
        # Удаляем комментарии тикета (и их вложения)
        TicketComment.query.filter_by(ticket_id=t.id).delete()
        db.session.delete(t)
        db.session.commit()
        flash('Тикет удалён.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.exception('Ошибка при удалении тикета: %s', e)
        flash('Ошибка при удалении тикета. Проверьте логи.', 'danger')
    return redirect(url_for('manager_tickets'))


@app.route('/ticket/<int:ticket_id>/export_pdf')
@login_required
def export_ticket_pdf(ticket_id):
    t = Ticket.query.get_or_404(ticket_id)
    # Права на экспорт: пользователь может экспортировать свои тикеты; support, manager и admin — любые
    if current_user.role == 'user' and t.creator_id != current_user.id:
        flash('У вас нет доступа к этому тикету.', 'warning')
        return redirect(url_for('dashboard'))
    if current_user.role not in ('user', 'support', 'manager', 'admin'):
        flash('Недостаточно прав для экспорта.', 'warning')
        return redirect(url_for('dashboard'))

    buffer = io.BytesIO()
    # Предпочитаем любой TTF в static/fonts; при отсутствии — пробуем системные пути
    font_found = False
    font_name = None
    fonts_dir = os.path.join(app.root_path, 'static', 'fonts')
    # Регистрируем первую найденную в проекте TTF в static/fonts
    try:
        if os.path.isdir(fonts_dir):
            for fname in os.listdir(fonts_dir):
                if fname.lower().endswith('.ttf'):
                    fp = os.path.join(fonts_dir, fname)
                    try:
                        candidate_name = os.path.splitext(fname)[0]
                        pdfmetrics.registerFont(TTFont(candidate_name, fp))
                        font_name = candidate_name
                        font_found = True
                        app.logger.info('Registered PDF font from %s', fp)
                        break
                    except Exception as e:
                        app.logger.exception('Failed registering project font %s: %s', fp, e)
    except Exception:
        pass

    # Резервный вариант: используем распространённый DejaVu TTF в системе
    if not font_found:
        system_paths = [
            '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
            '/usr/local/share/fonts/DejaVuSans.ttf',
        ]
        for fp in system_paths:
            try:
                if os.path.exists(fp):
                    candidate_name = os.path.splitext(os.path.basename(fp))[0]
                    pdfmetrics.registerFont(TTFont(candidate_name, fp))
                    font_name = candidate_name
                    font_found = True
                    app.logger.info('Registered PDF font from %s', fp)
                    break
            except Exception as e:
                app.logger.exception('Failed registering system font %s: %s', fp, e)

    p = pdf_canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    y = height - 50
    if font_found:
        p.setFont(font_name, 16)
    else:
        p.setFont('Times-Bold', 16)
    p.drawString(50, y, f"Тикет #{t.id}: {t.title}")
    y -= 30
    if font_found:
        p.setFont(font_name, 11)
    else:
        p.setFont('Times-Roman', 11)
    p.drawString(50, y, f"Статус: {get_status_label(t.status)}    Приоритет: {get_priority_label(t.priority)}")
    y -= 20
    # Информация об авторе (фамилия, имя, компания, адрес)
    creator_name = f"{t.creator.last_name or ''} {t.creator.first_name or ''}".strip()
    creator_company = t.creator.company_name or '—'
    creator_address = t.creator.address or '—'
    creator_phone = t.creator.phone or '—'
    p.drawString(50, y, f"Автор: {creator_name} — {creator_company}")
    y -= 18
    p.drawString(50, y, f"Адрес автора: {creator_address}")
    y -= 18
    p.drawString(50, y, f"Телефон автора: {creator_phone}")
    y -= 18
    p.drawString(50, y, f"Создано: {t.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 30
    if font_found:
        p.setFont(font_name, 12)
    else:
        p.setFont('Times-Bold', 12)
    p.drawString(50, y, "Описание:")
    y -= 18
    if font_found:
        p.setFont(font_name, 11)
    else:
        p.setFont('Helvetica', 11)
    for line in t.description.split('\n'):
        # Простая обёртка строк (наивная) для переноса в PDF
        parts = [line[i:i+90] for i in range(0, len(line), 90)]
        for part in parts:
            if y < 80:
                p.showPage()
                y = height - 50
            p.drawString(50, y, part)
            y -= 14
    y -= 10
    if font_found:
        p.setFont(font_name, 12)
    else:
        p.setFont('Helvetica-Bold', 12)
    p.drawString(50, y, 'Комментарии:')
    y -= 18
    if font_found:
        p.setFont(font_name, 10)
    else:
        p.setFont('Times-Roman', 10)
    comments = t.comments.order_by(TicketComment.created_at.asc()).all()
    for c in comments:
        author = f"{c.author.last_name or ''} {c.author.first_name or ''}".strip() or c.author.username
        created = c.created_at.strftime('%Y-%m-%d %H:%M')
        text = f"{created} — {author}: {c.content}"
        parts = [text[i:i+100] for i in range(0, len(text), 100)]
        for part in parts:
            if y < 80:
                p.showPage()
                y = height - 50
            p.drawString(50, y, part)
            y -= 12

    p.showPage()
    p.save()
    buffer.seek(0)
    # Используем параметр attachment_filename для совместимости со старыми версиями Flask
    try:
        return send_file(buffer, as_attachment=True, download_name=f'ticket_{t.id}.pdf', mimetype='application/pdf')
    except TypeError:
        return send_file(buffer, as_attachment=True, attachment_filename=f'ticket_{t.id}.pdf', mimetype='application/pdf')


@app.route('/support')
@login_required
def support_dashboard():
    if current_user.role != 'support':
        flash('Только техподдержка может видеть эту страницу.', 'warning')
        return redirect(url_for('dashboard'))
    open_tickets = Ticket.query.filter_by(status='open').order_by(Ticket.created_at.asc()).all()
    in_progress = Ticket.query.filter_by(status='in_progress', assignee_id=current_user.id).order_by(Ticket.updated_at.desc()).all()
    assigned_all = Ticket.query.filter_by(status='in_progress').order_by(Ticket.updated_at.desc()).all()
    return render_template('support_dashboard.html', open_tickets=open_tickets, in_progress=in_progress, assigned_all=assigned_all)


@app.route('/ticket/create', methods=['GET', 'POST'])
@login_required
def create_ticket():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        priority = request.form.get('priority', 'medium')
        file = request.files.get('attachment')

        if not title or not description:
            flash('Заголовок и описание обязателны.', 'danger')
            return redirect(url_for('create_ticket'))

        t = Ticket(title=title, description=description, priority=priority, creator_id=current_user.id)
        db.session.add(t)
        db.session.commit()

        # Обработка вложения при создании тикета (если файл был прислан)
        if file and file.filename != '':
            if not allowed_file(file.filename):
                flash('Тип файла не разрешён для загрузки.', 'warning')
            else:
                orig = secure_filename(file.filename)
                stored = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{orig}"
                path = os.path.join(app.config['UPLOAD_FOLDER'], stored)
                file.save(path)
                att = Attachment(filename=stored, original_name=orig, ticket_id=t.id, uploader_id=current_user.id)
                db.session.add(att)
                db.session.commit()

        flash('Тикет создан.', 'success')
        return redirect(url_for('user_dashboard'))
    return render_template('create_ticket.html')


@app.route('/ticket/<int:ticket_id>')
@login_required
def view_ticket(ticket_id):
    t = Ticket.query.get_or_404(ticket_id)
    # Безопасность: обычный пользователь видит только свои тикеты, support — все
    if current_user.role == 'user' and t.creator_id != current_user.id:
        flash('У вас нет доступа к этому тикету.', 'warning')
        return redirect(url_for('dashboard'))
    comments = t.comments.order_by(TicketComment.created_at.asc()).all()
    attachments = t.attachments.order_by(Attachment.created_at.asc()).all()
    return render_template('ticket.html', ticket=t, comments=comments, attachments=attachments)


@app.route('/ticket/<int:ticket_id>/take', methods=['POST'])
@login_required
def take_ticket(ticket_id):
    if current_user.role != 'support':
        flash('Только техподдержка может брать тикеты.', 'warning')
        return redirect(url_for('dashboard'))
    t = Ticket.query.get_or_404(ticket_id)
    if t.status != 'open':
        flash('Тикет уже в работе или закрыт.', 'info')
        return redirect(url_for('support_dashboard'))
    t.assignee_id = current_user.id
    t.status = 'in_progress'
    db.session.commit()
    flash('Вы взяли тикет в работу.', 'success')
    return redirect(url_for('view_ticket', ticket_id=ticket_id))


@app.route('/ticket/<int:ticket_id>/resolve', methods=['POST'])
@login_required
def resolve_ticket(ticket_id):
    t = Ticket.query.get_or_404(ticket_id)
    if current_user.role != 'support' or t.assignee_id != current_user.id:
        flash('Только ответственный исполнитель может закрыть тикет.', 'warning')
        return redirect(url_for('dashboard'))
    t.status = 'resolved'
    t.resolved_at = datetime.utcnow()
    db.session.commit()
    flash('Тикет помечен как выполненный.', 'success')
    return redirect(url_for('view_ticket', ticket_id=ticket_id))


@app.route('/ticket/<int:ticket_id>/comment', methods=['POST'])
@login_required
def comment_ticket(ticket_id):
    t = Ticket.query.get_or_404(ticket_id)
    # Право комментировать: пользователь — свои тикеты, support — любые
    if current_user.role == 'user' and t.creator_id != current_user.id:
        flash('У вас нет доступа к этому тикету.', 'warning')
        return redirect(url_for('dashboard'))

    content = request.form.get('content', '').strip()
    file = request.files.get('attachment')
    if not content and (not file or file.filename == ''):
        flash('Комментарий пустой.', 'warning')
        return redirect(url_for('view_ticket', ticket_id=ticket_id))

    comment = None
    if content:
        comment = TicketComment(ticket_id=t.id, author_id=current_user.id, content=content)
        db.session.add(comment)
        db.session.commit()

    if file and file.filename != '':
        if not allowed_file(file.filename):
            flash('Тип файла не разрешён для загрузки.', 'warning')
        else:
            orig = secure_filename(file.filename)
            stored = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{orig}"
            path = os.path.join(app.config['UPLOAD_FOLDER'], stored)
            file.save(path)
            att = Attachment(filename=stored, original_name=orig, ticket_id=t.id, uploader_id=current_user.id)
            if comment:
                att.comment_id = comment.id
            db.session.add(att)
            db.session.commit()

    flash('Комментарий добавлен.', 'success')
    return redirect(url_for('view_ticket', ticket_id=ticket_id))


@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    # Ищем attachment в БД, проверяем доступ
    att = Attachment.query.filter_by(filename=filename).first()
    if not att:
        abort(404)
    ticket = att.ticket
    # Разрешаем скачивать вложения: support может всё, автор тикета может свои, загрузивший может
    if current_user.role != 'support' and ticket and ticket.creator_id != current_user.id and att.uploader_id != current_user.id:
        flash('Нет доступа �� файлу.', 'warning')
        return redirect(url_for('dashboard'))
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True, attachment_filename=att.original_name)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)