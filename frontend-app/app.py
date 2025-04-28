import os
import sys
from bson import ObjectId
from flask import Flask, render_template, redirect, url_for, flash, request
from forms import RegistrationForm, LoginForm
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from datetime import datetime

class User(UserMixin):
    def __init__(self, id, username, email, password_hash, bio="", created_at=None):
        self.id = str(id)
        self.username = username
        self.email = email
        self._password_hash = password_hash
        self.bio = bio
        self.created_at = created_at or datetime.now().isoformat()
    
    def check_password(self, password):
        return check_password_hash(self._password_hash, password)

# Create Flask application
app = Flask(
    __name__,
    template_folder='templates',
    static_folder='static'
)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key_here')
app.config['UPLOAD_FOLDER'] = 'static/uploads'  # Fix upload path

# Ensure uploads directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# MongoDB Atlas connection
mongo_uri = "mongodb+srv://lgl1876523678:1017@cluster0.k8xwe.mongodb.net/?retryWrites=true&w=majority"
client = MongoClient(mongo_uri)
db = client['project5_db']    
users_collection = db['userInfo']
posts_collection = db['posts']
comments_collection = db['comments']

# Setup Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'auth.login'

@login_manager.user_loader
def load_user(user_id):
    user_doc = users_collection.find_one({"_id": ObjectId(user_id)})
    if user_doc:
        return User(
            user_doc['_id'],
            user_doc['username'],
            user_doc['email'],
            user_doc['password'],
            user_doc.get('bio', ''),
            user_doc.get('created_at')
        )
    return None

# Database utility functions
def get_post_comments(post_id):
    """Get comments for a specific post"""
    comments = list(comments_collection.find({"post_id": str(post_id)}).sort("created_at", 1))
    return comments

def get_user_by_username(username):
    """Get user by username"""
    user_doc = users_collection.find_one({"username": username})
    if user_doc:
        return User(
            user_doc['_id'],
            user_doc['username'],
            user_doc['email'],
            user_doc['password'],
            user_doc.get('bio', ''),
            user_doc.get('created_at')
        )
    return None

# Make utility functions available in templates
@app.context_processor
def utility_processor():
    return dict(
        get_post_comments=get_post_comments,
        get_user_by_username=get_user_by_username
    )

# Create blueprints
from flask import Blueprint

# Main blueprint
main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    return render_template('index.html')

@main_bp.route('/feed')
@login_required
def feed():
    posts = list(posts_collection.find().sort("created_at", -1))
    return render_template('feed.html', posts=posts)

@main_bp.route('/profile/<username>')
@login_required
def profile(username):
    user = get_user_by_username(username)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('main.feed'))
    
    posts = list(posts_collection.find({"author": username}).sort("created_at", -1))
    return render_template('profile.html', username=username, posts=posts)

@main_bp.route('/create-post', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        caption = request.form.get('caption')
        image = request.files.get('image')
        
        if not caption or not image:
            flash('Both caption and image are required!', 'danger')
            return render_template('create_post.html')
            
        # Save image
        filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{image.filename}"
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image.save(image_path)
        
        # Create post in database
        post_data = {
            "author": current_user.username,
            "image_url": f"/static/uploads/{filename}",  # Fix URL path
            "caption": caption,
            "created_at": datetime.now().isoformat()
        }
        
        result = posts_collection.insert_one(post_data)
        
        if result.inserted_id:
            flash('Post created successfully!', 'success')
            return redirect(url_for('main.feed'))
        else:
            flash('Failed to create post!', 'danger')
            
    return render_template('create_post.html')

@main_bp.route('/post/<post_id>/comment', methods=['POST'])
@login_required
def add_comment(post_id):
    text = request.form.get('text')
    
    if not text:
        flash('Comment text is required!', 'danger')
        return redirect(request.referrer or url_for('main.feed'))
        
    # Create comment in database
    comment_data = {
        "post_id": post_id,
        "commenter": current_user.username,
        "text": text,
        "created_at": datetime.now().isoformat()
    }
    
    result = comments_collection.insert_one(comment_data)
    
    if result.inserted_id:
        flash('Comment added!', 'success')
    else:
        flash('Failed to add comment!', 'danger')
        
    return redirect(request.referrer or url_for('main.feed'))

# Auth blueprint
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.feed'))
        
    form = RegistrationForm()

    if form.validate_on_submit():
        email = form.email.data
        username = form.username.data
        password = form.password.data

        # Email & Username Checking
        existing_user = users_collection.find_one({
            "$or": [{"email": email}, {"username": username}]
        })

        if existing_user:
            if existing_user.get('email') == email:
                flash('Email already registered!', 'danger')
            else:
                flash('Username already taken!', 'danger')
            return render_template('register.html', form=form)

        # Generate password hash
        hashed_password = generate_password_hash(password)

        # MongoDB Insertion
        new_user = {
            "email": email,
            "username": username,
            "password": hashed_password,
            "bio": "",
            "created_at": datetime.now().isoformat()
        }
        
        result = users_collection.insert_one(new_user)
        
        if result.inserted_id:
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash('Registration failed. Please try again.', 'danger')
    
    return render_template('register.html', form=form)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.feed'))
        
    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        # Find user by email
        user_doc = users_collection.find_one({"email": email})

        if user_doc and check_password_hash(user_doc['password'], password):
            # Login successful
            user = User(
                user_doc['_id'],
                user_doc['username'],
                user_doc['email'],
                user_doc['password'],
                user_doc.get('bio', ''),
                user_doc.get('created_at')
            )
            login_user(user)
            flash('Login successful!', 'success')
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.feed'))
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('main.index'))

# Register blueprints
app.register_blueprint(main_bp, url_prefix='/main')  # Use URL prefix
app.register_blueprint(auth_bp, url_prefix='/auth')

# Root redirect
@app.route('/')
def root():
    return redirect(url_for('main.index'))

if __name__ == '__main__':
    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5001)