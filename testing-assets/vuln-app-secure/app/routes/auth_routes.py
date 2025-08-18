from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from app import db
from app.models import User
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from app.utils import validate_username, validate_email, validate_password
import re

# Create auth blueprint
auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Validación de entrada
        if not username or not password:
            flash('Usuario y contraseña son requeridos', 'error')
            return render_template('login.html')
        
        # Validar formato de usuario (solo alfanumérico y algunos caracteres especiales)
        if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
            flash('Formato de usuario inválido', 'error')
            return render_template('login.html')
        
        # Autenticación segura usando solo ORM
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash(f'¡Bienvenido {user.username}!', 'success')
            return redirect(url_for('main.index'))
        
        flash('Usuario o contraseña inválidos', 'error')
    return render_template('login.html')

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        # Validate input
        valid_username, username_error = validate_username(username)
        if not valid_username:
            flash(username_error)
            return redirect(url_for('auth.register'))
        
        valid_email, email_error = validate_email(email)
        if not valid_email:
            flash(email_error)
            return redirect(url_for('auth.register'))
        
        valid_password, password_error = validate_password(password)
        if not valid_password:
            flash(password_error)
            return redirect(url_for('auth.register'))
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('auth.register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return redirect(url_for('auth.register'))
        
        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful')
        return redirect(url_for('auth.login'))
    
    return render_template('register.html')

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))
