from datetime import datetime
import uuid
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

# Mock database collections
mock_users = {}
mock_posts = []
mock_comments = []

class User(UserMixin):
    def __init__(self, id, username, password_hash, bio=""):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.bio = bio
        self.created_at = datetime.now().isoformat()
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "bio": self.bio,
            "created_at": self.created_at
        }

# User management functions
def register_user_mock(username, password, bio=""):
    """Register a new user with password hashing"""
    # Check if username already exists
    if username in mock_users:
        return False, "Username already taken"
    
    user_id = str(uuid.uuid4())
    password_hash = generate_password_hash(password)
    
    user = User(user_id, username, password_hash, bio)
    mock_users[username] = user
    
    return True, "User registered successfully"

def login_user_mock(username, password):
    """Authenticate a user with username and password"""
    user = mock_users.get(username)
    if user and user.check_password(password):
        return user
    return None

def get_user_by_id(user_id):
    """Get user by ID for Flask-Login"""
    for user in mock_users.values():
        if user.id == user_id:
            return user
    return None

def get_user_by_username(username):
    """Get user by username"""
    return mock_users.get(username)

# Post management functions
def add_mock_post(author, image_url, caption, created_at=None):
    """Add a mock post"""
    post_id = str(uuid.uuid4())
    post = {
        "_id": post_id,
        "author": author,
        "image_url": image_url,
        "caption": caption,
        "created_at": created_at or datetime.now().isoformat()
    }
    mock_posts.append(post)
    return post

def get_all_posts():
    """Get all posts for the feed, sorted by most recent first"""
    sorted_posts = sorted(mock_posts, key=lambda x: x["created_at"], reverse=True)
    return sorted_posts

def get_user_posts(username):
    """Get all posts by a specific user"""
    user_posts = [post for post in mock_posts if post["author"] == username]
    sorted_posts = sorted(user_posts, key=lambda x: x["created_at"], reverse=True)
    return sorted_posts

def get_post_by_id(post_id):
    """Get a specific post by ID"""
    for post in mock_posts:
        if post["_id"] == post_id:
            return post
    return None

def create_new_post(author, image_path, caption):
    """Create a new post with an image and caption"""
    # In a real app, this would handle the image upload to a cloud storage
    # For now, we'll just use the local path
    image_url = "/".join(image_path.split("/")[2:])  # Remove app/ from path
    
    post = add_mock_post(author, f"/{image_url}", caption)
    return post is not None

# Comment management functions
def add_mock_comment(post_id, commenter, text):
    """Add a mock comment"""
    comment_id = str(uuid.uuid4())
    comment = {
        "_id": comment_id,
        "post_id": post_id,
        "commenter": commenter,
        "text": text,
        "created_at": datetime.now().isoformat()
    }
    mock_comments.append(comment)
    return comment

def get_post_comments(post_id):
    """Get all comments for a specific post"""
    post_comments = [comment for comment in mock_comments if comment["post_id"] == post_id]
    sorted_comments = sorted(post_comments, key=lambda x: x["created_at"])
    return sorted_comments

def add_comment_to_post(post_id, commenter, text):
    """Add a comment to a post"""
    # Check if post exists
    post = get_post_by_id(post_id)
    if not post:
        return False
    
    comment = add_mock_comment(post_id, commenter, text)
    return comment is not None

# Initialize some mock data
def initialize_mock_data():
    """Initialize some mock data for testing"""
    # Create mock users with proper password hashing
    if not mock_users:
        register_user_mock("ppl1", "password123", "I love photography!")
        register_user_mock("pp2", "password123", "Software engineering student")
        register_user_mock("pp3", "password123", "Just sharing my daily life")
    
    # Add mock posts if there are none
    if not mock_posts:
        add_mock_post(
            "ppl1",
            "/static/images/sunset.jpg",
            "Amazing sunset view from my window today! 🌅",
            "2023-04-20T18:30:00"
        )
        add_mock_post(
            "pp2",
            "/static/images/code.jpg",
            "Just deployed my first full-stack app! 🚀 #coding #mongodb",
            "2023-04-21T10:15:00"
        )
        add_mock_post(
            "pp3",
            "/static/images/coffee.jpg",
            "Perfect morning coffee ☕",
            "2023-04-22T09:00:00"
        )
        
    # Add mock comments if there are none
    if not mock_comments and mock_posts:
        add_mock_comment(mock_posts[0]["_id"], "pp2", "Beautiful colors!")
        add_mock_comment(mock_posts[0]["_id"], "pp3", "Where was this taken?")
        if len(mock_posts) > 1:
            add_mock_comment(mock_posts[1]["_id"], "pp1", "Congratulations! What tech stack?")
        if len(mock_posts) > 2:
            add_mock_comment(mock_posts[2]["_id"], "pp2", "Looks delicious!")

# Note: We don't automatically initialize data when the module is imported anymore
# Instead, we'll call this function from app.py