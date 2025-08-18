from functools import wraps
from flask import abort, flash, redirect, url_for
from flask_login import current_user
from app.models import Document, User

def admin_required(f):
    """Decorator to require admin privileges."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page')
            return redirect(url_for('auth.login'))
        
        if not current_user.is_admin:
            flash('Admin privileges required')
            abort(403)
        
        return f(*args, **kwargs)
    return decorated_function

def document_access_required(f):
    """Decorator to check document access permissions."""
    @wraps(f)
    def decorated_function(doc_id, *args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page')
            return redirect(url_for('auth.login'))
        
        document = Document.query.get_or_404(doc_id)
        
        # Allow access if user owns the document or is admin
        if document.user_id != current_user.id and not current_user.is_admin:
            flash('You do not have permission to access this document')
            abort(403)
        
        return f(doc_id, *args, **kwargs)
    return decorated_function

def profile_access_required(f):
    """Decorator to check profile access permissions."""
    @wraps(f)
    def decorated_function(user_id, *args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page')
            return redirect(url_for('auth.login'))
        
        # Allow access if viewing own profile or is admin
        if user_id != current_user.id and not current_user.is_admin:
            flash('You do not have permission to view this profile')
            abort(403)
        
        return f(user_id, *args, **kwargs)
    return decorated_function

def can_access_document(user, document):
    """Check if user can access a document."""
    if not user.is_authenticated:
        return False
    
    return document.user_id == user.id or user.is_admin

def can_access_profile(user, target_user_id):
    """Check if user can access a profile."""
    if not user.is_authenticated:
        return False
    
    return target_user_id == user.id or user.is_admin

def can_delete_user(user, target_user):
    """Check if user can delete another user."""
    if not user.is_authenticated or not user.is_admin:
        return False
    
    # Prevent admin from deleting themselves
    if target_user.id == user.id:
        return False
    
    # Prevent non-super-admin from deleting other admins
    if target_user.is_admin and not getattr(user, 'is_super_admin', False):
        return False
    
    return True

def can_modify_document(user, document):
    """Check if user can modify a document."""
    if not user.is_authenticated:
        return False
    
    return document.user_id == user.id or user.is_admin

def can_comment_on_document(user, document):
    """Check if user can comment on a document."""
    if not user.is_authenticated:
        return False
    
    # Users can comment on their own documents or if they're admin
    return document.user_id == user.id or user.is_admin

def rate_limit_check(user, action_type, max_actions=10, time_window=3600):
    """Basic rate limiting check (simplified implementation)."""
    # This is a simplified rate limiting check
    # In production, you would use Redis or similar for proper rate limiting
    
    if not user.is_authenticated:
        return False
    
    # Admin users have higher limits
    if user.is_admin:
        max_actions *= 2
    
    # For now, just return True (implement proper rate limiting in production)
    return True