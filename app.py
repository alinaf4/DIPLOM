import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()

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


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(200), nullable=False, unique=True)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')  # 'user' or 'support'
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
    status = db.Column(db.String(50), nullable=False, default='open')  # open, in_progress, resolved
    priority = db.Column(db.String(20), nullable=False, default='medium')  # low, medium, high
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
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
    filename = db.Column(db.String(300), nullable=False)       # stored filename
    original_name = db.Column(db.String(300), nullable=False)  # original filename
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'), nullable=True)
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comment_id = db.Column(db.Integer, db.ForeignKey('ticket_comment.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def create_tables():
    # проверяем существующие таблицы через инспектор SQLAlchemy
    missing = []
    try:
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        existing_tables = set(inspector.get_table_names())
        required_tables = {'user', 'ticket', 'ticket_comment', 'attachment'}
        missing = list(required_tables - existing_tables)
    except Exception as e:
        app.logger.exception('DB inspection failed: %s', e)
        # при неудаче попробуем всё же создать таблицы
        missing = ['unknown']

    if missing:
        try:
            app.logger.info('Missing tables detected: %s. Creating tables...', ','.join(missing))
            db.create_all()
            app.logger.info('Tables created (if they did not exist).')
        except Exception as e:
            app.logger.exception('Failed to create tables: %s', e)

    # ensure default admin user exists
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


# Some Flask versions (or alternative WSGI entrypoints) may not support
# the `before_first_request` decorator at import time inside the container.
# Ensure DB/tables/admin are initialized now using the app context.
try:
    with app.app_context():
        create_tables()
except Exception as e:
    app.logger.exception('Error while initializing DB at import time: %s', e)


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
    # admin has special users management page
    if current_user.role == 'admin':
        return redirect(url_for('admin_users'))
    if current_user.role == 'support':
        return redirect(url_for('support_dashboard'))
    return redirect(url_for('user_dashboard'))


@app.route('/admin/users')
@login_required
def admin_users():
    # only admin (created default) can access this
    if current_user.role != 'admin':
        flash('Доступ запрещён.', 'warning')
        return redirect(url_for('dashboard'))
    users = User.query.order_by(User.created_at.asc()).all()
    roles = ['user', 'support', 'admin']
    return render_template('admin_users.html', users=users, roles=roles)


@app.route('/admin/users/<int:user_id>/role', methods=['POST'])
@login_required
def admin_set_role(user_id):
    if current_user.role != 'admin':
        flash('Доступ запрещён.', 'warning')
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')
    if new_role not in ('user', 'support', 'admin'):
        flash('Недопустимая роль.', 'danger')
        return redirect(url_for('admin_users'))
    # prevent removing last admin? simple check: allow change but avoid locking self out
    if user.id == current_user.id and new_role != 'admin':
        flash('Нельзя изменить свою собственную роль.', 'warning')
        return redirect(url_for('admin_users'))
    user.role = new_role
    db.session.commit()
    flash('Роль обновлена.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/user')
@login_required
def user_dashboard():
    if current_user.role != 'user':
        flash('Только пользователи могут видеть эту страницу.', 'warning')
        return redirect(url_for('dashboard'))
    tickets = Ticket.query.filter_by(creator_id=current_user.id).order_by(Ticket.created_at.desc()).all()
    return render_template('user_dashboard.html', tickets=tickets)


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

        # обработка вложения при создании тикета (если есть)
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
    # security: users can view only their tickets, support can view all
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
    db.session.commit()
    flash('Тикет помечен как выполненный.', 'success')
    return redirect(url_for('view_ticket', ticket_id=ticket_id))


@app.route('/ticket/<int:ticket_id>/comment', methods=['POST'])
@login_required
def comment_ticket(ticket_id):
    t = Ticket.query.get_or_404(ticket_id)
    # permission: user can comment on own ticket, support can comment on any
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