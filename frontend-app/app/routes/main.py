from flask import Blueprint, render_template, redirect, url_for, request, flash, current_app
from flask_login import login_required, current_user
from app.mock_data import get_all_posts, get_user_posts, get_post_comments, create_new_post, add_comment_to_post

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('main.feed'))
    return render_template('index.html')

@main_bp.route('/feed')
@login_required
def feed():
    posts = get_all_posts()
    return render_template('feed.html', posts=posts)

@main_bp.route('/profile/<username>')
@login_required
def profile(username):
    posts = get_user_posts(username)
    return render_template('profile.html', username=username, posts=posts)

@main_bp.route('/create-post', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        caption = request.form.get('caption')
        image = request.files.get('image')
        
        if not caption or not image:
            flash('Both caption and image are required!', 'error')
            return render_template('create_post.html')
            
        # Save image to a temporary location (in a real app, this would save to storage)
        image_path = f"app/static/uploads/{image.filename}"
        image.save(image_path)
        
        # Create post with mock data (will be replaced with API call)
        success = create_new_post(current_user.username, image_path, caption)
        
        if success:
            flash('Post created successfully!', 'success')
            return redirect(url_for('main.feed'))
        else:
            flash('Failed to create post!', 'error')
            
    return render_template('create_post.html')

@main_bp.route('/post/<post_id>/comment', methods=['POST'])
@login_required
def add_comment(post_id):
    text = request.form.get('text')
    
    if not text:
        flash('Comment text is required!', 'error')
        return redirect(request.referrer or url_for('main.feed'))
        
    success = add_comment_to_post(post_id, current_user.username, text)
    
    if success:
        flash('Comment added!', 'success')
    else:
        flash('Failed to add comment!', 'error')
        
    return redirect(request.referrer or url_for('main.feed'))