import re
import os
from werkzeug.utils import secure_filename
from flask import current_app

def validate_username(username):
    """Validate username format and length."""
    if not username or not isinstance(username, str):
        return False, "Username is required"
    
    if len(username) < 3 or len(username) > 50:
        return False, "Username must be between 3 and 50 characters"
    
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"
    
    return True, None

def validate_email(email):
    """Validate email format."""
    if not email or not isinstance(email, str):
        return False, "Email is required"
    
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return False, "Invalid email format"
    
    if len(email) > 254:
        return False, "Email is too long"
    
    return True, None

def validate_password(password):
    """Validate password strength."""
    if not password or not isinstance(password, str):
        return False, "Password is required"
    
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if len(password) > 128:
        return False, "Password is too long"
    
    # Check for at least one uppercase, one lowercase, one digit
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    
    return True, None

def validate_search_query(query):
    """Validate search query to prevent injection attacks."""
    if not query or not isinstance(query, str):
        return False, "Search query is required"
    
    # Remove leading/trailing whitespace
    query = query.strip()
    
    if len(query) < 1:
        return False, "Search query cannot be empty"
    
    if len(query) > 100:
        return False, "Search query is too long"
    
    # Block potentially dangerous characters
    dangerous_chars = ['<', '>', '"', "'", ';', '--', '/*', '*/', 'script']
    query_lower = query.lower()
    
    for char in dangerous_chars:
        if char in query_lower:
            return False, "Search query contains invalid characters"
    
    return True, query

def validate_comment_content(content):
    """Validate comment content."""
    if not content or not isinstance(content, str):
        return False, "Comment content is required"
    
    content = content.strip()
    
    if len(content) < 1:
        return False, "Comment cannot be empty"
    
    if len(content) > 1000:
        return False, "Comment is too long (max 1000 characters)"
    
    return True, content

def validate_file_upload(file):
    """Validate uploaded file."""
    if not file or not file.filename:
        return False, "No file selected", None
    
    # Check file size (handled by Flask config MAX_CONTENT_LENGTH)
    
    # Validate filename
    filename = secure_filename(file.filename)
    if not filename:
        return False, "Invalid filename", None
    
    # Check file extension
    allowed_extensions = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}
    if '.' not in filename or filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
        return False, "File type not allowed", None
    
    # Additional filename validation
    if len(filename) > 255:
        return False, "Filename is too long", None
    
    return True, None, filename

def sanitize_html_content(content):
    """Basic HTML sanitization for display."""
    if not content:
        return ""
    
    # Replace dangerous HTML characters
    content = content.replace('&', '&amp;')
    content = content.replace('<', '&lt;')
    content = content.replace('>', '&gt;')
    content = content.replace('"', '&quot;')
    content = content.replace("'", '&#x27;')
    
    return content

def validate_document_title(title):
    """Validate document title."""
    if not title or not isinstance(title, str):
        return False, "Document title is required"
    
    title = title.strip()
    
    if len(title) < 1:
        return False, "Document title cannot be empty"
    
    if len(title) > 200:
        return False, "Document title is too long (max 200 characters)"
    
    return True, title