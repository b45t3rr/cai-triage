from flask import Blueprint, jsonify, request, current_app
from app import db
import requests
from functools import wraps
import os
from urllib.parse import urlparse
import ipaddress
from app.access_control import admin_required, can_delete_user
import time
from collections import defaultdict, deque

# Create API blueprint
api = Blueprint('api', __name__, url_prefix='/api')

# API key authentication - should be set via environment variable in production
API_KEYS = [os.getenv('API_KEY', 'secure_api_key_change_in_production_789xyz!')]

# Whitelist of allowed domains for SSRF protection
ALLOWED_DOMAINS = [
    'httpbin.org',
    'jsonplaceholder.typicode.com',
    'api.github.com',
    'www.google.com',
    'example.com'
]

# Additional allowed domains from environment (comma-separated)
if os.getenv('ALLOWED_DOMAINS'):
    ALLOWED_DOMAINS.extend([domain.strip() for domain in os.getenv('ALLOWED_DOMAINS').split(',')])

# Rate limiting configuration
RATE_LIMIT_WINDOW = 300  # 5 minutes
RATE_LIMIT_MAX_REQUESTS = 10  # Max requests per window
rate_limit_storage = defaultdict(lambda: deque())

def check_rate_limit(api_key):
    """Check if API key has exceeded rate limit"""
    now = time.time()
    requests_log = rate_limit_storage[api_key]
    
    # Remove old requests outside the window
    while requests_log and requests_log[0] < now - RATE_LIMIT_WINDOW:
        requests_log.popleft()
    
    # Check if limit exceeded
    if len(requests_log) >= RATE_LIMIT_MAX_REQUESTS:
        return False, f"Rate limit exceeded. Max {RATE_LIMIT_MAX_REQUESTS} requests per {RATE_LIMIT_WINDOW//60} minutes"
    
    # Add current request
    requests_log.append(now)
    return True, "Rate limit OK"

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.args.get('api_key')
        if api_key in API_KEYS:
            return f(*args, **kwargs)
        return jsonify({"error": "Invalid API key"}), 403
    return decorated

def is_safe_url(url):
    """Validate if URL is safe to fetch (prevents SSRF)"""
    try:
        parsed = urlparse(url)
        
        # Only allow HTTP and HTTPS
        if parsed.scheme not in ['http', 'https']:
            return False, "Only HTTP and HTTPS schemes are allowed"
        
        # Block localhost and private networks
        hostname = parsed.hostname
        if not hostname:
            return False, "Invalid hostname"
        
        # Whitelist approach: only allow explicitly permitted domains
        if hostname not in ALLOWED_DOMAINS:
            return False, f"Domain '{hostname}' is not in the allowed domains list"
        
        # Enhanced IP validation for both IPv4 and IPv6
        try:
            ip = ipaddress.ip_address(hostname)
            # Block all private, loopback, link-local, and multicast addresses
            if (ip.is_private or ip.is_loopback or ip.is_link_local or 
                ip.is_multicast or ip.is_reserved):
                return False, "Private/internal IP addresses are not allowed"
            
            # Additional IPv6 checks
            if isinstance(ip, ipaddress.IPv6Address):
                # Block IPv6 unique local addresses (fc00::/7)
                if ip.packed[0] & 0xfe == 0xfc:
                    return False, "IPv6 unique local addresses are not allowed"
                # Block IPv6 site-local addresses (deprecated but still blocked)
                if ip.packed[0] & 0xfe == 0xfe and ip.packed[1] & 0xc0 == 0xc0:
                    return False, "IPv6 site-local addresses are not allowed"
        except ValueError:
            # Not an IP address, additional hostname checks
            hostname_lower = hostname.lower()
            
            # Block various localhost representations
            localhost_variants = ['localhost', 'localhost.localdomain', '0.0.0.0', '0']
            if hostname_lower in localhost_variants:
                return False, "Localhost access is not allowed"
            
            # Block private domain patterns
            private_patterns = ['.local', '.internal', '.corp', '.home', '.lan']
            if any(hostname_lower.endswith(pattern) for pattern in private_patterns):
                return False, "Private domain access is not allowed"
        
        # Enhanced port validation - block dangerous ports
        dangerous_ports = {
            22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 69: 'TFTP',
            110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP',
            389: 'LDAP', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
            1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            5984: 'CouchDB', 6379: 'Redis', 8080: 'HTTP-Alt', 9200: 'Elasticsearch',
            11211: 'Memcached', 27017: 'MongoDB'
        }
        
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        if port in dangerous_ports:
            return False, f"Access to {dangerous_ports[port]} port ({port}) is not allowed"
        
        # Block non-standard HTTP ports that might be used for internal services
        if port not in [80, 443, 8080, 8443] and port < 1024:
            return False, f"Access to privileged port {port} is not allowed"
        
        return True, "URL is safe"
    except Exception as e:
        return False, f"URL validation error: {str(e)}"

@api.route('/fetch')
@require_api_key
def fetch_url():
    # Enhanced SSRF protection with rate limiting and improved logging
    api_key = request.args.get('api_key')
    url = request.args.get('url')
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'unknown'))
    
    if not url:
        current_app.logger.warning(f"Missing URL parameter from IP: {client_ip}, API key: {api_key[:8]}...")
        return jsonify({"error": "URL parameter is required"}), 400
    
    # Check rate limiting
    rate_ok, rate_message = check_rate_limit(api_key)
    if not rate_ok:
        current_app.logger.warning(f"Rate limit exceeded for API key: {api_key[:8]}..., IP: {client_ip}, URL: {url}")
        return jsonify({"error": rate_message}), 429
    
    # Validate URL safety
    is_safe, message = is_safe_url(url)
    if not is_safe:
        current_app.logger.warning(f"SSRF attempt blocked - IP: {client_ip}, API key: {api_key[:8]}..., URL: {url}, Reason: {message}")
        return jsonify({"error": f"URL not allowed: {message}"}), 403
    
    # Log successful validation
    current_app.logger.info(f"Fetching URL - IP: {client_ip}, API key: {api_key[:8]}..., URL: {url}")
    
    try:
        # Safe request with enhanced security measures
        response = requests.get(
            url, 
            timeout=10,  # Increased timeout for legitimate requests
            verify=True,  # Enable SSL verification
            allow_redirects=False,  # Prevent redirect-based SSRF
            headers={
                'User-Agent': 'SecureApp/1.0',
                'Accept': 'text/html,application/json,text/plain,*/*;q=0.8'
            },
            stream=True  # Stream response to check size before loading
        )
        
        # Check content type before processing
        content_type = response.headers.get('content-type', '').lower()
        allowed_content_types = ['text/', 'application/json', 'application/xml']
        if not any(content_type.startswith(ct) for ct in allowed_content_types):
            current_app.logger.warning(f"Blocked unsafe content type: {content_type} for URL: {url}")
            return jsonify({"error": f"Content type '{content_type}' not allowed"}), 403
        
        # Read response with size limit
        content = b''
        max_size = 1024 * 1024  # 1MB limit
        for chunk in response.iter_content(chunk_size=8192):
            content += chunk
            if len(content) > max_size:
                current_app.logger.warning(f"Response too large for URL: {url}, size: {len(content)}")
                return jsonify({"error": "Response too large (max 1MB)"}), 413
        
        # Decode content safely
        try:
            text_content = content.decode('utf-8', errors='replace')
        except Exception:
            text_content = content.decode('latin-1', errors='replace')
        
        # Log successful fetch
        current_app.logger.info(f"Successfully fetched URL: {url}, size: {len(content)}, content-type: {content_type}")
        
        # Return limited response information
        return jsonify({
            "status_code": response.status_code,
            "content_length": len(content),
            "content_type": content_type,
            "content": text_content[:1000],  # Limit content to first 1000 chars
            "headers": dict(list(response.headers.items())[:10])  # Limit headers returned
        })
        
    except requests.exceptions.Timeout:
        current_app.logger.error(f"Timeout fetching URL: {url}")
        return jsonify({"error": "Request timeout"}), 408
    except requests.exceptions.SSLError as e:
        current_app.logger.error(f"SSL error fetching URL: {url}, error: {str(e)}")
        return jsonify({"error": "SSL verification failed"}), 400
    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"Request failed for URL: {url}, error: {str(e)}")
        return jsonify({"error": "Failed to fetch URL"}), 500

@api.route('/admin/users')
@require_api_key
@admin_required
def list_users():
    # Fixed IDOR vulnerability - require admin authorization
    from app.models import User
    
    users = User.query.all()
    # Return limited user information
    return jsonify([{"id": u.id, "username": u.username, "email": u.email, "is_admin": u.is_admin} for u in users])

@api.route('/admin/delete', methods=['POST'])
@require_api_key
@admin_required
def delete_user():
    # Fixed IDOR vulnerability - use access control function
    from app.models import User
    from flask_login import current_user
    
    user_id = request.json.get('user_id') if request.json else None
    if not user_id:
        return jsonify({"error": "user_id is required"}), 400
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Use access control function to check permissions
    if not can_delete_user(current_user, user):
        return jsonify({"error": "Insufficient permissions to delete this user"}), 403
    
    try:
        db.session.delete(user)
        db.session.commit()
        current_app.logger.info(f"Admin {current_user.username} deleted user {user.username}")
        return jsonify({"status": "success", "message": f"User {user.username} deleted"})
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting user: {str(e)}")
        return jsonify({"error": "Failed to delete user"}), 500
