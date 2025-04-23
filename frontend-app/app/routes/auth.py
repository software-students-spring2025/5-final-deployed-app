from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required
from app.mock_data import login_user_mock, register_user_mock, User

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # In a real application, this would validate against the database
        user = login_user_mock(username, password)
        
        if user:
            # Use Flask-Login to manage the user session
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('main.feed'))
        else:
            flash('Invalid username or password', 'error')
            
    return render_template('login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        bio = request.form.get('bio', '')
        
        # In a real application, this would create a user in the database
        success, message = register_user_mock(username, password, bio)
        
        if success:
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash(message, 'error')
            
    return render_template('register.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('main.index'))