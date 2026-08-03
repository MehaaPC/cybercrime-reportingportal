import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import (
    StringField, PasswordField, TextAreaField, SelectField, SubmitField
)
from wtforms.validators import DataRequired, Email, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import requests
from dotenv import load_dotenv

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-this-to-a-random-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cybercrime.db'
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB max upload

load_dotenv()
GROQ_API_KEY = os.environ.get('GROQ_API_KEY')
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

CRIME_TYPES = [
    'Phishing / Fraud Email', 'Online Financial Fraud', 'Social Media Hacking',
    'Cyberbullying / Harassment', 'Identity Theft', 'Ransomware / Malware',
    'Fake Job / Lottery Scam', 'Data Breach', 'Other'
]

STATUS_LIST = ['Pending', 'Under Investigation', 'Resolved', 'Rejected']


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='citizen')
    reports = db.relationship('Report', backref='reporter', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    complaint_no = db.Column(db.String(20), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    crime_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(200), nullable=False)
    evidence_file = db.Column(db.String(300))
    status = db.Column(db.String(30), default='Pending')
    date_filed = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class RegisterForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm = PasswordField('Confirm Password',
                             validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class ReportForm(FlaskForm):
    crime_type = SelectField('Type of Cyber Crime', choices=[(c, c) for c in CRIME_TYPES],
                              validators=[DataRequired()])
    description = TextAreaField('Describe the incident', validators=[DataRequired(), Length(min=20)])
    location = StringField('Location (City / State)', validators=[DataRequired()])
    evidence = FileField('Upload Evidence (screenshot, PDF, etc.)',
                          validators=[FileAllowed(['jpg', 'jpeg', 'png', 'pdf'],
                                                   'Only images or PDF allowed!')])
    submit = SubmitField('Submit Report')


class StatusForm(FlaskForm):
    status = SelectField('Update Status', choices=[(s, s) for s in STATUS_LIST],
                          validators=[DataRequired()])
    submit = SubmitField('Update')


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegisterForm()
    if form.validate_on_submit():
        existing = User.query.filter_by(email=form.email.data).first()
        if existing:
            flash('Email already registered. Please log in.', 'warning')
            return redirect(url_for('login'))
        user = User(name=form.name.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Logged in successfully.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))


@app.route('/report', methods=['GET', 'POST'])
@login_required
def report_crime():
    form = ReportForm()
    if form.validate_on_submit():
        filename = None
        if form.evidence.data:
            file = form.evidence.data
            filename = secure_filename(f"{current_user.id}_{datetime.utcnow().timestamp()}_{file.filename}")
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        complaint_no = f"CCR{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        new_report = Report(
            complaint_no=complaint_no,
            user_id=current_user.id,
            crime_type=form.crime_type.data,
            description=form.description.data,
            location=form.location.data,
            evidence_file=filename,
        )
        db.session.add(new_report)
        db.session.commit()
        flash(f'Report submitted successfully! Your complaint number is {complaint_no}', 'success')
        return redirect(url_for('my_reports'))
    return render_template('report_form.html', form=form)


@app.route('/my-reports')
@login_required
def my_reports():
    reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.date_filed.desc()).all()
    return render_template('my_reports.html', reports=reports)


def admin_required(func):
    from functools import wraps
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)
        return func(*args, **kwargs)
    return wrapper


@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    reports = Report.query.order_by(Report.date_filed.desc()).all()
    stats = {
        'total': len(reports),
        'pending': sum(1 for r in reports if r.status == 'Pending'),
        'investigating': sum(1 for r in reports if r.status == 'Under Investigation'),
        'resolved': sum(1 for r in reports if r.status == 'Resolved'),
    }
    return render_template('admin_dashboard.html', reports=reports, stats=stats)


@app.route('/admin/report/<int:report_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_report_detail(report_id):
    report = Report.query.get_or_404(report_id)
    form = StatusForm(status=report.status)
    if form.validate_on_submit():
        report.status = form.status.data
        db.session.commit()
        flash('Status updated.', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_report_detail.html', report=report, form=form)


@app.route('/chatbot', methods=['POST'])
def chatbot():
    user_message = request.json.get('message', '')

    system_context = (
        "You are a helpful assistant on a Cyber Crime Reporting Portal. "
        "You help users in two ways: (1) guide them on how to file a cyber crime report "
        "on this website (steps: Register/Login -> click 'File a Report' -> select crime type, "
        "describe the incident, add location, optionally attach evidence -> Submit -> they get a "
        "complaint number and can track status under 'My Reports'), and (2) answer general cyber "
        "safety questions (phishing, passwords, scams, online fraud, 2FA, safe browsing). "
        "Keep answers short, clear, and reassuring. If asked something unrelated to cyber safety "
        "or this portal, politely redirect back to those topics."
    )

    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {"role": "system", "content": system_context},
            {"role": "user", "content": user_message}
        ]
    }
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(GROQ_URL, json=payload, headers=headers, timeout=15)
        data = response.json()
        reply = data['choices'][0]['message']['content']
    except Exception as e:
        reply = f"DEBUG ERROR: {str(e)} | RAW: {data}"

    return {"reply": reply}

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(email='admin@portal.com').first():
            admin = User(name='Admin', email='admin@portal.com', role='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True)