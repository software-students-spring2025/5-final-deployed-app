from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
import re

# Enhanced Gmail validator function
def validate_gmail(form, field):
    """
    Enhanced Gmail validator that checks:
    1. Email ends with @gmail.com
    2. Email follows basic Gmail format rules
    """
    email = field.data.lower()
    if not email.endswith('@gmail.com'):
        raise ValidationError('Only Gmail addresses (@gmail.com) are allowed.')
    
    # Simple pattern to validate Gmail username format
    # Gmail usernames must be between 6-30 characters and contain only letters, numbers, periods
    username = email.split('@')[0]
    if not re.match(r'^[a-zA-Z0-9.]{6,30}$', username) or '..' in username:
        raise ValidationError('Invalid Gmail format. Please check your email address.')

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(), 
        Email(),
        validate_gmail  # Add enhanced validator
    ])
    username = StringField('Username', validators=[DataRequired(), Length(3, 20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(), 
        Email(),
        validate_gmail  # Add enhanced validator
    ])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')