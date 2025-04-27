import sys
import os
from mock_data import get_post_comments, get_user_by_username
from flask import Flask, render_template, redirect, url_for, flash, Blueprint
from flask_wtf import FlaskForm
from forms import RegistrationForm
from pymongo import MongoClient
from werkzeug.security import generate_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user
from db.mongo_client import get_user_collection
from forms import LoginForm
from werkzeug.security import check_password_hash
from flask_login import UserMixin

class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = str(id)  
        self.username = username
        self.password_hash = password_hash


# Create Flask application
app = Flask(
    __name__,
   template_folder='frontend-app/templates',
    static_folder='frontend-app/static'
)
app.config['SECRET_KEY'] = 'your_secret_key_here'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/feed')
def feed():
    return render_template('feed.html')

# MongoDB Atlas connection
mongo_uri = "mongodb+srv://lgl1876523678:1017@cluster0.k8xwe.mongodb.net/?retryWrites=true&w=majority"
client = MongoClient(mongo_uri)
db = client['project5_db']    
users_collection = db['userInfo']
# Get User By ID
def get_user_by_id(user_id):
    user = users_collection.find_one({"_id": user_id})
    if user:
        return User(user['_id'], user['username'], user['password'])
    return None

# Setup Flask-Login loader
login_manager = LoginManager(app)
login_manager.login_view = 'auth.login'

@login_manager.user_loader
def load_user(user_id):
    return get_user_by_id(user_id)

# Make functions available in templates
@app.context_processor
def utility_processor():
    return dict(
        get_post_comments=get_post_comments,
        get_user_by_username=get_user_by_username
    )
# Register 
auth_bp = Blueprint('auth', __name__)
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        email = form.email.data
        username = form.username.data
        password = form.password.data

        # Email & Username Checking
        existing_user = users_collection.find_one({
            "$or": [{"email": email}]
        })

        if existing_user:
            flash('Email already been used！', 'danger')
            return redirect(url_for('auth.register'))

        hashed_password = generate_password_hash(password)

        # MongoDB Insertion
        users_collection.insert_one({
            "email": email,
            "username": username,
            "password": hashed_password
        })

        flash('Register Success！', 'success')
        return redirect(url_for('auth.login'))  
    else:
        return render_template('register.html', form=form)

@auth_bp.route('/login')
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        # 查找数据库中是否有这个email的用户
        user = users_collection.find_one({"email": email})

        if user and check_password_hash(user['password'], password):
            # 登录成功，建立session
            user_obj = User(user['_id'], user['username'], user['password'])  # 需要你有一个User类（像之前mock_data里一样）
            login_user(user_obj)
            flash('Login Success！', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('auth.login'))

    return render_template('login.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('main.index'))

app.register_blueprint(auth_bp, url_prefix='/auth')

# Ensure uploads directory exists
import os
os.makedirs('app/static/uploads', exist_ok=True)

if __name__ == '__main__':
    
    
    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5001)