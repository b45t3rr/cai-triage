from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import os
from dotenv import load_dotenv

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()

# Load environment variables
load_dotenv()

def create_app():
    app = Flask(__name__)
    
    # Load configuration with secure defaults
    secret_key = os.getenv('SECRET_KEY')
    if not secret_key or secret_key == 'insecure_secret_key_123':
        import secrets
        secret_key = secrets.token_hex(32)
        app.logger.warning('Using generated SECRET_KEY. Set SECRET_KEY environment variable for production.')
    
    app.config['SECRET_KEY'] = secret_key
    app.config['SQLALCHEMY_DATABASE_URI'] = (
        f"mysql+mysqlconnector://"
        f"{os.getenv('MYSQL_USER', 'vulnuser')}:"
        f"{os.getenv('MYSQL_PASSWORD', 'secure_random_password_123!')}@"
        f"{os.getenv('MYSQL_HOST', 'db')}/"
        f"{os.getenv('MYSQL_DATABASE', 'vulnapp')}"
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Additional security configurations
    app.config['SESSION_COOKIE_SECURE'] = os.getenv('FLASK_ENV') == 'production'
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file upload
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'
    
    # Register blueprints
    from app.routes.main_routes import main
    from app.routes.auth_routes import auth
    from app.routes.api_routes import api
    
    app.register_blueprint(main)
    app.register_blueprint(auth)
    app.register_blueprint(api, url_prefix='/api')
    
    # Create database tables
    with app.app_context():
        db.create_all()
    
    return app

# Create the application instance
app = create_app()

@login_manager.user_loader
def load_user(user_id):
    from app.models import User
    return User.query.get(int(user_id))
