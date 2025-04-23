from app import create_app
from app.mock_data import initialize_mock_data, get_user_by_id

# Create Flask application
app = create_app()

# Setup Flask-Login loader
from flask_login import LoginManager
login_manager = LoginManager(app)
login_manager.login_view = 'auth.login'

@login_manager.user_loader
def load_user(user_id):
    return get_user_by_id(user_id)

# Make functions available in templates
@app.context_processor
def utility_processor():
    from app.mock_data import get_post_comments, get_user_by_username
    return dict(
        get_post_comments=get_post_comments,
        get_user_by_username=get_user_by_username
    )

# Ensure uploads directory exists
import os
os.makedirs('app/static/uploads', exist_ok=True)

if __name__ == '__main__':
    # Initialize mock data for demonstration
    initialize_mock_data()
    
    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5001)