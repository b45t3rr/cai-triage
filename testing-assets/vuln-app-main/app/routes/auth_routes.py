from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from app import db
from app.models import User
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector

# Deshabilitar advertencias de seguridad
import warnings
warnings.filterwarnings('ignore', category=Warning)

# Create auth blueprint
auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Primero intentar login legítimo usando ORM
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash(f'¡Bienvenido {user.username}!', 'success')
            return redirect(url_for('main.index'))
        
        # Si el login normal falla, intentar con consulta SQL vulnerable
        try:
            # Conexión directa a la base de datos sin usar ORM
            conn = mysql.connector.connect(
                host='db',
                user='root',
                password='insecure_password',
                database='vulnapp',
                auth_plugin='mysql_native_password'
            )
            
            # Crear un cursor que devuelva diccionarios
            cursor = conn.cursor(dictionary=True)
            
            # Inyección SQL vulnerable - permite bypass con payloads como: ' OR '1'='1' --
            query = f"SELECT * FROM user WHERE username = '{username}' AND (password_hash = '{password}' OR '{password}' = 'bypass')"
            
            current_app.logger.error(f"[VULN] Query: {query}")
            
            cursor.execute(query)
            user_data = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if user_data:
                # Si la consulta SQL retorna datos, el login es exitoso
                user = User(
                    id=user_data['id'],
                    username=user_data['username'],
                    email=user_data['email'],
                    is_admin=bool(user_data.get('is_admin', False))
                )
                user.password_hash = user_data['password_hash']
                
                login_user(user)
                flash(f'¡Bienvenido {user.username}! (SQL Bypass)', 'success')
                return redirect(url_for('main.index'))
                
        except Exception as e:
            current_app.logger.error(f"[ERROR] {str(e)}")
            flash('Error en la autenticación', 'error')
            
        flash('Usuario o contraseña inválidos', 'error')
    return render_template('login.html')

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('auth.register'))
            
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('auth.login'))
    return render_template('register.html')

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))
