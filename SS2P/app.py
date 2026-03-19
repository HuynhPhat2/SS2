import os
import secrets
from flask import Flask, render_template, redirect, url_for, session, request
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from datetime import timedelta
from dotenv import load_dotenv

# Tải biến môi trường từ file .env
load_dotenv()

# Khởi tạo Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(16))
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Cấu hình database SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ===================== MODEL USER =====================
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100))
    picture = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    
    def __repr__(self):
        return f'<User {self.email}>'

# ===================== CẤU HÌNH GOOGLE OAUTH =====================
oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
        'prompt': 'select_account'
    }
)

# ===================== DECORATOR KIỂM TRA ĐĂNG NHẬP =====================
def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            session['next_url'] = request.url
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# ===================== ROUTES =====================

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/google-login')
def google_login():
    # Hardcode redirect_uri theo yêu cầu
    redirect_uri = 'http://127.0.0.1:5000/google/callback'
    
    # Tạo state token chống CSRF
    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    
    return google.authorize_redirect(redirect_uri, state=state)

# Route callback đã đổi thành /google/callback
@app.route('/google/callback')
def callback():
    # Kiểm tra state
    if request.args.get('state') != session.get('oauth_state'):
        return 'State mismatch - possible CSRF attack', 400
    
    try:
        token = google.authorize_access_token()
        user_info = google.get('https://www.googleapis.com/oauth2/v3/userinfo').json()
        
        google_id = user_info['sub']
        email = user_info['email']
        name = user_info.get('name', email.split('@')[0])
        picture = user_info.get('picture', '')
        
        user = User.query.filter_by(google_id=google_id).first()
        if not user:
            user = User(
                google_id=google_id,
                email=email,
                name=name,
                picture=picture
            )
            db.session.add(user)
            db.session.commit()
        
        session.permanent = True
        session['user_id'] = user.id
        session['user_name'] = user.name
        session['user_email'] = user.email
        session['user_picture'] = user.picture
        
        session.pop('oauth_state', None)
        
        next_url = session.pop('next_url', url_for('dashboard'))
        return redirect(next_url)
        
    except Exception as e:
        return f"Đã xảy ra lỗi: {str(e)}", 500

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template(
        'dashboard.html',
        name=session.get('user_name'),
        email=session.get('user_email'),
        picture=session.get('user_picture')
    )

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    return "Profile page - coming soon!"

# ===================== TẠO DATABASE =====================
with app.app_context():
    db.create_all()
    print("✅ Database created successfully!")

# ===================== CHẠY ỨNG DỤNG =====================
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
