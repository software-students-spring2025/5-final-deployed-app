import os
import sys
from bson import ObjectId
from flask import Flask, render_template, redirect, url_for, flash, request
from dotenv import load_dotenv
from forms import RegistrationForm, LoginForm
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from datetime import datetime
from flask import send_file
from io import BytesIO

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

load_dotenv()

# Create Flask application
app = Flask(
    __name__,
    template_folder='templates',
    static_folder='static'
)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_dev_key')
app.config['UPLOAD_FOLDER'] = 'static/uploads'  # Fix upload path

# Ensure uploads directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# MongoDB Atlas connection
mongo_uri = os.environ.get("MONGO_URI")
client = MongoClient(mongo_uri)
db = client['project5_db']    
users_collection = db['userInfo']
posts_collection = db['posts']
comments_collection = db['comments']
follows_collection = db['follows']  # New collection to store user follow relationships

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

def get_followers(username):
    """Get the list of users following a specified user"""
    followers_docs = list(follows_collection.find({"following": username}))
    
    # Get complete user information
    followers = []
    for doc in followers_docs:
        user_doc = users_collection.find_one({"username": doc["follower"]})
        if user_doc:
            follower = User(
                user_doc['_id'],
                user_doc['username'],
                user_doc['email'],
                user_doc['password'],
                user_doc.get('bio', ''),
                user_doc.get('created_at')
            )
            # Add follow timestamp
            follower.followed_at = doc.get("created_at")
            followers.append(follower)
    
    return followers

def get_following(username):
    """Get the list of users that a specified user is following"""
    following_docs = list(follows_collection.find({"follower": username}))
    
    # Get complete user information
    following = []
    for doc in following_docs:
        user_doc = users_collection.find_one({"username": doc["following"]})
        if user_doc:
            followed_user = User(
                user_doc['_id'],
                user_doc['username'],
                user_doc['email'],
                user_doc['password'],
                user_doc.get('bio', ''),
                user_doc.get('created_at')
            )
            # Add follow timestamp
            followed_user.following_since = doc.get("created_at")
            following.append(followed_user)
    
    return following

def is_following(follower_username, followed_username):
    """Check if a user is following another user"""
    return follows_collection.find_one({
        "follower": follower_username,
        "following": followed_username
    }) is not None

# Make utility functions available in templates
@app.context_processor
def utility_processor():
    return dict(
        get_post_comments=get_post_comments,
        get_user_by_username=get_user_by_username,
        get_followers=get_followers,
        get_following=get_following,
        is_following=is_following
    )

# Create blueprints
from flask import Blueprint

# Main blueprint
main_bp = Blueprint('main', __name__)

@main_bp.route('/image/<post_id>')
def serve_image(post_id):
    post = posts_collection.find_one({"_id": ObjectId(post_id)})
    if not post or 'image_data' not in post:
        flash('Image not found', 'danger')
        return redirect(url_for('main.feed'))
    
    image_data = post['image_data']
    mimetype = post.get('image_mimetype', 'image/jpeg')
    
    return send_file(BytesIO(image_data), mimetype=mimetype)

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
            
        # Revised Image Storage Method
        image_data = image.read()
        
        # Create post in database
        post_data = {
        "author": current_user.username,
        "caption": caption,
        "created_at": datetime.now().isoformat(),
        "image_data": image_data,  
        "image_mimetype": image.mimetype   
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

@main_bp.route('/post/<post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    # Find the post
    post = posts_collection.find_one({"_id": ObjectId(post_id)})
    
    if not post:
        flash('Post not found', 'danger')
        return redirect(url_for('main.feed'))
        
    # Check if current user is the author
    if post['author'] != current_user.username:
        flash('You can only delete your own posts', 'danger')
        return redirect(url_for('main.feed'))
        
    # Delete the post's comments
    comments_collection.delete_many({"post_id": str(post_id)})
    
    # Delete the post
    posts_collection.delete_one({"_id": ObjectId(post_id)})
    
    flash('Post deleted successfully', 'success')
    return redirect(url_for('main.feed'))

@main_bp.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        email = request.form.get('email')
        bio = request.form.get('bio')
        
        # Check if email is already used by another user
        existing_user = users_collection.find_one({
            "email": email,
            "_id": {"$ne": ObjectId(current_user.id)}
        })
        
        if existing_user:
            flash('Email already registered by another user!', 'danger')
            return render_template('edit_profile.html')
        
        # Handle avatar upload
        avatar_filename = None
        if 'avatar' in request.files and request.files['avatar'].filename:
            avatar = request.files['avatar']
            if avatar:
                # Ensure filename is secure
                avatar_filename = secure_filename(f"{current_user.username}_{datetime.now().strftime('%Y%m%d%H%M%S')}.jpg")
                avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], avatar_filename)
                avatar.save(avatar_path)
        
        # Update database
        update_data = {
            "email": email,
            "bio": bio
        }
        
        if avatar_filename:
            update_data["avatar"] = f"/static/uploads/{avatar_filename}"
        
        users_collection.update_one(
            {"_id": ObjectId(current_user.id)},
            {"$set": update_data}
        )
        
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('main.profile', username=current_user.username))
    
    return render_template('edit_profile.html')

@main_bp.route('/follow/<username>', methods=['POST'])
@login_required
def follow(username):
    # Check if user to follow exists
    user_to_follow = get_user_by_username(username)
    if not user_to_follow:
        flash('User not found', 'danger')
        return redirect(url_for('main.feed'))
    
    # Check if already following
    if is_following(current_user.username, username):
        flash(f'You are already following {username}', 'info')
        return redirect(url_for('main.profile', username=username))
    
    # Cannot follow self
    if current_user.username == username:
        flash('You cannot follow yourself', 'danger')
        return redirect(url_for('main.profile', username=username))
    
    # Create follow relationship
    follow_data = {
        "follower": current_user.username,
        "following": username,
        "created_at": datetime.now().isoformat()
    }
    
    follows_collection.insert_one(follow_data)
    
    flash(f'You are now following {username}', 'success')
    return redirect(url_for('main.profile', username=username))

@main_bp.route('/unfollow/<username>', methods=['POST'])
@login_required
def unfollow(username):
    # Check if user to unfollow exists
    user_to_unfollow = get_user_by_username(username)
    if not user_to_unfollow:
        flash('User not found', 'danger')
        return redirect(url_for('main.feed'))
    
    # Check if already following
    if not is_following(current_user.username, username):
        flash(f'You are not following {username}', 'info')
        return redirect(url_for('main.profile', username=username))
    
    # Delete follow relationship
    follows_collection.delete_one({
        "follower": current_user.username,
        "following": username
    })
    
    flash(f'You have unfollowed {username}', 'success')
    return redirect(url_for('main.profile', username=username))

@main_bp.route('/profile/<username>/followers')
@login_required
def followers(username):
    # Check if user exists
    user = get_user_by_username(username)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('main.feed'))
    
    followers = get_followers(username)
    return render_template('followers.html', username=username, followers=followers)

@main_bp.route('/profile/<username>/following')
@login_required
def following(username):
    # Check if user exists
    user = get_user_by_username(username)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('main.feed'))
    
    following = get_following(username)
    return render_template('following.html', username=username, following=following)

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