import os
import sys
import re
from bson import ObjectId
from flask import Flask, render_template, redirect, url_for, flash, request, session, abort
from markupsafe import Markup
from dotenv import load_dotenv
from forms import RegistrationForm, LoginForm
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from datetime import datetime
from flask import send_file
from io import BytesIO

# User authentication libraries
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from authlib.integrations.flask_client import OAuth
import requests

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

load_dotenv()

# Create Flask application
app = Flask(
    __name__,
    template_folder='templates',
    static_folder='static'
)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_dev_key')
app.config['UPLOAD_FOLDER'] = 'static/uploads'  # Upload path

# Ensure uploads directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Configure Flask-Mail
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() in ['true', '1', 't']
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

mail = Mail(app)

# Create token serializer
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Configure OAuth with improved configuration
oauth = OAuth(app)
oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
    # Redirect URI will be set dynamically in each route
    redirect_uri=None
)

# MongoDB Atlas connection
mongo_uri = os.environ.get("MONGO_URI")
client = MongoClient(mongo_uri)
db = client['project5_db']    
users_collection = db['userInfo']
posts_collection = db['posts']
comments_collection = db['comments']
follows_collection = db['follows']  # Collection to store user follow relationships

# User model
class User(UserMixin):
    def __init__(self, id, username, email, password_hash, bio="", created_at=None, email_verified=False, google_id=None):
        self.id = str(id)
        self.username = username
        self.email = email
        self._password_hash = password_hash
        self.bio = bio
        self.created_at = created_at or datetime.now().isoformat()
        self.email_verified = email_verified
        self.google_id = google_id
    
    def check_password(self, password):
        return check_password_hash(self._password_hash, password)

# Setup Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'auth.login'

@login_manager.user_loader
def load_user(user_id):
    """Load user from database by user_id"""
    user_doc = users_collection.find_one({"_id": ObjectId(user_id)})
    if user_doc:
        return User(
            user_doc['_id'],
            user_doc['username'],
            user_doc['email'],
            user_doc['password'],
            user_doc.get('bio', ''),
            user_doc.get('created_at'),
            user_doc.get('email_verified', False),
            user_doc.get('google_id')
        )
    return None

# Enhanced Gmail validation function
def validate_gmail_format(email):
    """
    Validate a Gmail address format
    Returns (is_valid, error_message)
    """
    if not email.lower().endswith('@gmail.com'):
        return False, "Only Gmail addresses (@gmail.com) are allowed."
    
    # Simple pattern to validate Gmail username format
    username = email.split('@')[0]
    if not re.match(r'^[a-zA-Z0-9.]{6,30}$', username) or '..' in username:
        return False, "Invalid Gmail format. Please check your email address."
        
    return True, None

# Email verification helper function optimized for Gmail
def send_verification_email(user_email, username):
    """Send verification email to Gmail users with improved error handling"""
    # Ensure it's a Gmail address with proper format
    is_valid, error = validate_gmail_format(user_email)
    if not is_valid:
        app.logger.warning(f"Invalid Gmail format: {user_email} - {error}")
        return False
        
    token = serializer.dumps(user_email, salt='email-verification')
    
    verification_url = url_for(
        'auth.verify_email', 
        token=token, 
        _external=True
    )
    
    msg = Message('Confirm Your MiniShare Account', recipients=[user_email])
    msg.body = f'''Hello {username},
    
Thank you for registering with MiniShare! Please confirm your email address by clicking on the link below:

{verification_url}

If you did not register for MiniShare, please ignore this email.

Best regards,
The MiniShare Team
'''
    # For Gmail addresses, we use the regular mail sending
    try:
        mail.send(msg)
        app.logger.info(f"Verification email sent to: {user_email}")
        return True
    except Exception as e:
        app.logger.error(f"Error sending email: {e}")
        
        # For development, print the verification link
        if app.config['DEBUG']:
            print("\n============= VERIFICATION LINK =============")
            print(f"For: {user_email}")
            print(verification_url)
            print("============================================\n")
            
        return False

# Debug helper for OAuth sessions
def debug_session():
    """Helper function to log current session data"""
    if app.config['DEBUG']:
        session_data = {key: session[key] for key in session}
        app.logger.debug(f"Current session data: {session_data}")

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
            user_doc.get('created_at'),
            user_doc.get('email_verified', False),
            user_doc.get('google_id')
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
                user_doc.get('created_at'),
                user_doc.get('email_verified', False),
                user_doc.get('google_id')
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
                user_doc.get('created_at'),
                user_doc.get('email_verified', False),
                user_doc.get('google_id')
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
        is_following=is_following,
        config=app.config  # Make config available for test_gmail template
    )

# Create blueprints
from flask import Blueprint

# Main blueprint
main_bp = Blueprint('main', __name__)

@main_bp.route('/image/<post_id>')
def serve_image(post_id):
    """Serve post image from database"""
    post = posts_collection.find_one({"_id": ObjectId(post_id)})
    if not post or 'image_data' not in post:
        flash('Image not found', 'danger')
        return redirect(url_for('main.feed'))
    
    image_data = post['image_data']
    mimetype = post.get('image_mimetype', 'image/jpeg')
    
    return send_file(BytesIO(image_data), mimetype=mimetype)

@main_bp.route('/')
def index():
    """Landing page"""
    return render_template('index.html')

@main_bp.route('/feed')
@login_required
def feed():
    """User feed showing all posts"""
    posts = list(posts_collection.find().sort("created_at", -1))
    return render_template('feed.html', posts=posts)

@main_bp.route('/profile/<username>')
@login_required
def profile(username):
    """User profile page"""
    user = get_user_by_username(username)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('main.feed'))
    
    posts = list(posts_collection.find({"author": username}).sort("created_at", -1))
    return render_template('profile.html', username=username, posts=posts)

@main_bp.route('/create-post', methods=['GET', 'POST'])
@login_required
def create_post():
    """Create a new post"""
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
    """Add a comment to a post"""
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
    """Edit user profile"""
    if request.method == 'POST':
        email = request.form.get('email')
        bio = request.form.get('bio')
        
        # Validate Gmail address format
        is_valid, error = validate_gmail_format(email)
        if not is_valid:
            flash(error, 'danger')
            return render_template('edit_profile.html')
            
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
    """Follow a user"""
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
    """Unfollow a user"""
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
    """Show users that follow the given username"""
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
    """Show users that the given username is following"""
    # Check if user exists
    user = get_user_by_username(username)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('main.feed'))
    
    following = get_following(username)
    return render_template('following.html', username=username, following=following)

# New route for linking Google account to existing account
@main_bp.route('/link-google')
@login_required
def link_google():
    """Link current user account to Google"""
    # Store the current user ID in session
    session['link_account'] = current_user.id
    app.logger.info(f"User {current_user.username} initiating Google account linking")
    
    # Generate redirect URI
    redirect_uri = url_for('auth.google_link_callback', _external=True)
    
    # Redirect to Google login
    return oauth.google.authorize_redirect(redirect_uri)

# Auth blueprint
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Register a new user with enhanced validation"""
    if current_user.is_authenticated:
        return redirect(url_for('main.feed'))
        
    form = RegistrationForm()

    if form.validate_on_submit():
        email = form.email.data.lower()
        username = form.username.data
        password = form.password.data

        # Enhanced Gmail validation
        is_valid, error = validate_gmail_format(email)
        if not is_valid:
            flash(error, 'danger')
            return render_template('register.html', form=form)

        # Email & Username Checking
        existing_user = users_collection.find_one({
            "$or": [{"email": email}, {"username": username}]
        })

        if existing_user:
            if existing_user.get('email') == email:
                flash('Email already registered! Please log in or use Google Sign-in.', 'danger')
            else:
                flash('Username already taken!', 'danger')
            return render_template('register.html', form=form)

        # Generate password hash
        hashed_password = generate_password_hash(password)

        # Try to send verification email first before creating account
        email_sent = send_verification_email(email, username)
        
        if not email_sent and not app.config['DEBUG']:
            flash('Unable to send verification email. Please check your email address or try Google Sign-in.', 'danger')
            return render_template('register.html', form=form)

        # MongoDB Insertion
        new_user = {
            "email": email,
            "username": username,
            "password": hashed_password,
            "bio": "",
            "created_at": datetime.now().isoformat(),
            "email_verified": False  # Not verified until email confirmation
        }
        
        result = users_collection.insert_one(new_user)
        
        if result.inserted_id:
            if email_sent:
                flash('Registration successful! Please check your Gmail inbox to verify your account.', 'success')
            else:
                # In development mode, provide a direct verification option
                if app.config['DEBUG']:
                    token = serializer.dumps(email, salt='email-verification')
                    verification_url = url_for('auth.verify_email', token=token, _external=True)
                    flash(Markup(f'Registration successful! <a href="{verification_url}" target="_blank">Click here to verify your account</a> (Development only).'), 'success')
                else:
                    flash('Registration successful! We could not send a verification email. Please try signing in with Google instead.', 'warning')
            
            return redirect(url_for('auth.login'))
        else:
            flash('Registration failed. Please try again.', 'danger')
    
    return render_template('register.html', form=form)

@auth_bp.route('/verify-email/<token>')
def verify_email(token):
    """Verify user email with token - enhanced with better error handling"""
    try:
        email = serializer.loads(token, salt='email-verification', max_age=86400)  # 24 hour expiration
        app.logger.info(f"Verifying email: {email}")
        
        # Find user and update verification status
        user = users_collection.find_one({"email": email})
        
        if user:
            users_collection.update_one(
                {"email": email},
                {"$set": {"email_verified": True}}
            )
            flash('Your email has been verified! You can now log in.', 'success')
        else:
            app.logger.warning(f"Verification failed - User not found with email: {email}")
            flash('Invalid verification link. User not found with this email.', 'danger')
            
    except SignatureExpired:
        app.logger.warning("Verification failed - Token expired")
        flash('The verification link has expired. Please request a new one.', 'danger')
    except Exception as e:
        app.logger.error(f"Verification failed - Error: {str(e)}")
        flash(f'Invalid verification link. Error: {str(e)}', 'danger')
        
    return redirect(url_for('auth.login'))

@auth_bp.route('/resend-verification')
def resend_verification():
    """Resend email verification link with improved validation"""
    email = request.args.get('email', '')
    
    if current_user.is_authenticated:
        if current_user.email_verified:
            flash('Your email is already verified.', 'info')
            return redirect(url_for('main.feed'))
            
        # Validate email format before sending
        is_valid, error = validate_gmail_format(current_user.email)
        if not is_valid:
            flash(f'Cannot send verification email: {error}', 'danger')
            return redirect(url_for('main.feed'))
            
        try:
            if send_verification_email(current_user.email, current_user.username):
                flash('A new verification email has been sent. Please check your inbox.', 'success')
            else:
                flash('Could not send verification email. Please check your email address.', 'danger')
        except Exception as e:
            app.logger.error(f"Error sending verification email: {e}")
            flash('Could not send verification email. Please try again later.', 'danger')
    elif email:
        # Handle case when user is not logged in but provided email
        # Validate email format first
        is_valid, error = validate_gmail_format(email)
        if not is_valid:
            flash(f'Cannot send verification email: {error}', 'danger')
            return redirect(url_for('auth.login'))
            
        user = users_collection.find_one({"email": email})
        if user:
            try:
                if send_verification_email(email, user['username']):
                    flash('A new verification email has been sent. Please check your inbox.', 'success')
                else:
                    flash('Could not send verification email. Please check your email address.', 'danger')
            except Exception as e:
                app.logger.error(f"Error sending verification email: {e}")
                flash('Could not send verification email. Please try again later.', 'danger')
        else:
            flash('Email not found.', 'danger')
    else:
        flash('Please log in first or provide an email address.', 'info')
        
    return redirect(url_for('auth.login'))

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login with enhanced validation and logging"""
    if current_user.is_authenticated:
        return redirect(url_for('main.feed'))
        
    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data.lower()
        password = form.password.data
        
        app.logger.info(f"Login attempt for email: {email}")
        
        # Validate Gmail format
        is_valid, error = validate_gmail_format(email)
        if not is_valid:
            flash(error, 'danger')
            return render_template('login.html', form=form)

        # Find user by email
        user_doc = users_collection.find_one({"email": email})

        if user_doc and check_password_hash(user_doc['password'], password):
            # Check if email is verified
            if not user_doc.get('email_verified', False):
                app.logger.warning(f"Login attempt for unverified email: {email}")
                flash('Please verify your email before logging in. Check your Gmail inbox or request a new verification email.', 'warning')
                return render_template('login.html', form=form, show_resend=True, email=email)
                
            # Login successful
            app.logger.info(f"Login successful for user: {user_doc['username']}")
            user = User(
                user_doc['_id'],
                user_doc['username'],
                user_doc['email'],
                user_doc['password'],
                user_doc.get('bio', ''),
                user_doc.get('created_at'),
                user_doc.get('email_verified', False),
                user_doc.get('google_id')
            )
            login_user(user)
            flash('Login successful!', 'success')
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.feed'))
        else:
            # If the user exists but password is wrong, suggest Google login
            if user_doc:
                app.logger.warning(f"Failed login attempt (wrong password) for: {email}")
                flash(Markup('Invalid password. Consider <a href="/auth/login/google">signing in with Google</a> for easier access.'), 'danger')
            else:
                app.logger.warning(f"Failed login attempt (email not found): {email}")
                flash('Email not found. Please register or use Google login.', 'danger')

    return render_template('login.html', form=form, show_resend=False)

@auth_bp.route('/login/google')
def google_login():
    """Initiate Google OAuth login with improved debugging"""
    # Store the next URL if provided
    next_url = request.args.get('next')
    if next_url:
        session['next_url'] = next_url
        app.logger.debug(f"Stored next_url in session: {next_url}")
        
    # Generate explicit redirect URI
    redirect_uri = url_for('auth.google_authorize', _external=True)
    
    app.logger.info(f"Initiating Google login for IP: {request.remote_addr}")
    app.logger.debug(f"Google login redirect URI: {redirect_uri}")
    
    # Explicitly set the redirect_uri in the authorization request
    return oauth.google.authorize_redirect(redirect_uri)

@auth_bp.route('/login/google/callback')
def google_authorize():
    """Handle Google OAuth callback for login/signup with improved error handling"""
    app.logger.info(f"Google callback received from IP: {request.remote_addr}")
    
    try:
        token = oauth.google.authorize_access_token()
        app.logger.debug("Successfully obtained access token")
        
        resp = oauth.google.parse_id_token(token, None)
        
        # Extract user info
        google_id = resp.get('sub')
        email = resp.get('email')
        name = resp.get('name')
        picture = resp.get('picture')
        
        app.logger.info(f"Google auth successful for email: {email}")
        
        # Ensure it's a Gmail address
        if not email.lower().endswith('@gmail.com'):
            app.logger.warning(f"Non-Gmail address detected in Google OAuth: {email}")
            flash('Only Gmail addresses are supported. Please use a Gmail account.', 'danger')
            return redirect(url_for('auth.login'))
        
        # First, check if a user is already associated with this Google ID
        user_by_google_id = users_collection.find_one({"google_id": google_id})
        
        if user_by_google_id:
            # User already exists and is linked to this Google account
            app.logger.info(f"User found by Google ID: {user_by_google_id['username']}")
            
            user = User(
                user_by_google_id['_id'],
                user_by_google_id['username'],
                user_by_google_id['email'],
                user_by_google_id['password'],
                user_by_google_id.get('bio', ''),
                user_by_google_id.get('created_at'),
                user_by_google_id.get('email_verified', True),
                user_by_google_id.get('google_id')
            )
            login_user(user)
            flash('Login with Google successful!', 'success')
        else:
            # No user found with this Google ID, check by email
            user_by_email = users_collection.find_one({"email": email})
            
            if user_by_email:
                # User exists with this email but not linked to Google
                app.logger.info(f"User found by email, linking Google ID: {user_by_email['username']}")
                
                users_collection.update_one(
                    {"_id": user_by_email['_id']},
                    {"$set": {
                        "google_id": google_id,
                        "email_verified": True,
                        "profile_picture": picture
                    }}
                )
                
                user = User(
                    user_by_email['_id'],
                    user_by_email['username'],
                    user_by_email['email'],
                    user_by_email['password'],
                    user_by_email.get('bio', ''),
                    user_by_email.get('created_at'),
                    True,  # Now verified
                    google_id
                )
                login_user(user)
                flash('Your account has been linked to Google and is now verified.', 'success')
            else:
                # No existing user with this email, create a new account
                app.logger.info(f"Creating new user for Google account: {email}")
                
                # Generate username based on email
                username_base = email.split('@')[0]
                username = username_base
                
                # Check if username exists, add numbers until unique
                counter = 1
                while users_collection.find_one({"username": username}):
                    username = f"{username_base}{counter}"
                    counter += 1
                
                app.logger.debug(f"Generated unique username: {username}")
                
                # Create new user
                new_user = {
                    "email": email,
                    "username": username,
                    "password": generate_password_hash(f"google_{google_id}"),  # Create a password they can't guess
                    "bio": "",
                    "created_at": datetime.now().isoformat(),
                    "email_verified": True,  # Google already verified the email
                    "google_id": google_id,
                    "profile_picture": picture
                }
                
                result = users_collection.insert_one(new_user)
                user_id = result.inserted_id
                
                # Log in the new user
                app.logger.info(f"New Google user created with ID: {user_id}")
                
                user_doc = users_collection.find_one({"_id": user_id})
                user = User(
                    user_doc['_id'],
                    user_doc['username'],
                    user_doc['email'],
                    user_doc['password'],
                    user_doc.get('bio', ''),
                    user_doc.get('created_at'),
                    user_doc.get('email_verified', True),
                    user_doc.get('google_id')
                )
                login_user(user)
                flash('Your account has been created and you are now logged in!', 'success')
        
        # Retrieve next URL from session
        next_url = session.pop('next_url', None)
        app.logger.debug(f"Redirecting to: {next_url or url_for('main.feed')}")
        return redirect(next_url or url_for('main.feed'))
        
    except Exception as e:
        app.logger.error(f"Error during Google login: {str(e)}", exc_info=True)
        flash('Google login failed. Please try again or register with your Gmail address.', 'danger')
        return redirect(url_for('auth.login'))

@auth_bp.route('/google-link-callback')
@login_required
def google_link_callback():
    """Handle Google OAuth callback for linking accounts with improved error handling"""
    app.logger.info(f"Google link callback received for user: {current_user.username}")
    
    try:
        token = oauth.google.authorize_access_token()
        resp = oauth.google.parse_id_token(token, None)
        
        # Extract Google info
        google_id = resp.get('sub')
        email = resp.get('email')
        picture = resp.get('picture')
        
        app.logger.info(f"Google account info - Email: {email}, ID: {google_id}")
        
        # Ensure it's a Gmail address
        if not email.lower().endswith('@gmail.com'):
            flash('Only Gmail addresses are supported. Please use a Gmail account.', 'danger')
            return redirect(url_for('main.profile', username=current_user.username))
        
        # Check if this Google ID is already linked to another account
        existing_google_user = users_collection.find_one({
            "google_id": google_id,
            "_id": {"$ne": ObjectId(current_user.id)}
        })
        
        if existing_google_user:
            app.logger.warning(f"Google ID already linked to user: {existing_google_user['username']}")
            flash('This Google account is already linked to another user.', 'danger')
            return redirect(url_for('main.profile', username=current_user.username))
        
        # Ensure email matches current user or isn't used by another user
        if email.lower() != current_user.email.lower():
            existing_email_user = users_collection.find_one({
                "email": email,
                "_id": {"$ne": ObjectId(current_user.id)}
            })
            
            if existing_email_user:
                app.logger.warning(f"Google email already used by user: {existing_email_user['username']}")
                flash('The Google account email is already used by another MiniShare account.', 'danger')
                return redirect(url_for('main.profile', username=current_user.username))
                
            # Email different but not used by anyone else - update user's email
            app.logger.info(f"Updating user email from {current_user.email} to {email}")
            flash(f'Your email will be updated to match your Google account ({email}).', 'info')
        
        # Update user with Google info
        users_collection.update_one(
            {"_id": ObjectId(current_user.id)},
            {"$set": {
                "google_id": google_id,
                "email": email,  # Update email to match Google account
                "email_verified": True,
                "profile_picture": picture
            }}
        )
        
        flash('Your account has been successfully linked to Google!', 'success')
        return redirect(url_for('main.profile', username=current_user.username))
        
    except Exception as e:
        app.logger.error(f"Error linking Google account: {str(e)}", exc_info=True)
        flash('Failed to link Google account. Please try again.', 'danger')
        return redirect(url_for('main.profile', username=current_user.username))

@auth_bp.route('/logout')
@login_required
def logout():
    """Log out the current user"""
    username = current_user.username
    logout_user()
    app.logger.info(f"User logged out: {username}")
    flash('You have been logged out.', 'success')
    return redirect(url_for('main.index'))

@auth_bp.route('/test-gmail', methods=['GET', 'POST'])
def test_gmail():
    """A simple route to test Gmail sending functionality"""
    # Only available in debug mode
    if not app.config['DEBUG']:
        abort(404)
        
    if request.method == 'POST':
        test_email = request.form.get('test_email', '')
        
        # Validate Gmail format
        is_valid, error = validate_gmail_format(test_email)
        if not is_valid:
            return render_template('test_gmail.html', error=error)
            
        try:
            msg = Message('MiniShare Test Email', recipients=[test_email])
            msg.body = f'''Hello from MiniShare!
            
This is a test email to verify that our email system is working correctly.
If you received this, it means our Gmail configuration is working properly.

Time sent: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Best regards,
The MiniShare Team
'''
            mail.send(msg)
            app.logger.info(f"Test email sent to: {test_email}")
            return render_template('test_gmail.html', success=f"Test email sent to {test_email}. Please check your inbox.")
        except Exception as e:
            app.logger.error(f"Test email sending failed: {str(e)}")
            return render_template('test_gmail.html', error=f"Failed to send email: {str(e)}")
            
    return render_template('test_gmail.html')

# Register blueprints
app.register_blueprint(main_bp, url_prefix='/main')  # Use URL prefix
app.register_blueprint(auth_bp, url_prefix='/auth')

# Root redirect
@app.route('/')
def root():
    """Redirect root to main index"""
    return redirect(url_for('main.index'))

if __name__ == '__main__':
    # Run the application
    app.run(debug=app.config['DEBUG'], host='0.0.0.0', port=5001)