import sys
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_from_directory, current_app, abort, send_file
from app import db
from app.models import Document, Comment, User
from flask_login import login_required, current_user
from app.utils import validate_search_query, validate_comment_content, validate_file_upload, validate_document_title, sanitize_html_content
from app.access_control import document_access_required, profile_access_required, can_comment_on_document
import os
from werkzeug.utils import secure_filename

# Create main blueprint
main = Blueprint('main', __name__)

@main.route('/')
def index():
    # Fixed SQL Injection vulnerability - using ORM with parameterized queries
    search_query = request.args.get('q', '')
    if search_query:
        # Validate search query
        valid_search, validated_query = validate_search_query(search_query)
        if not valid_search:
            flash(validated_query)  # Error message
            documents = Document.query.all()
        else:
            # Safe parameterized query using SQLAlchemy ORM
            documents = Document.query.filter(Document.title.like(f'%{validated_query}%')).all()
    else:
        documents = Document.query.all()
    return render_template('index.html', documents=documents)

@main.route('/document/<int:doc_id>')
@login_required
@document_access_required
def view_document(doc_id):
    document = Document.query.get_or_404(doc_id)
    comments = Comment.query.filter_by(document_id=doc_id).all()
    return render_template('document.html', document=document, comments=comments)

@main.route('/profile/<int:user_id>')
@login_required
@profile_access_required
def view_profile(user_id):
    user = User.query.get_or_404(user_id)
    
    # Prepare user data with appropriate access control
    user_data = {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'is_admin': user.is_admin
    }
    
    return render_template('profile.html', user=user_data)

@main.route('/document/upload', methods=['POST'])
@login_required
def upload_document():
    # Validate title
    title = request.form.get('title', '').strip()
    valid_title, validated_title = validate_document_title(title)
    if not valid_title:
        flash(validated_title)
        return redirect(url_for('main.index'))
    
    # Validate content
    content = request.form.get('content', '').strip()
    if len(content) > 5000:
        flash('Document content is too long (max 5000 characters)')
        return redirect(url_for('main.index'))
    
    # Sanitize content
    sanitized_content = sanitize_html_content(content)
    
    # Handle file upload if present
    file_path = None
    if 'file' in request.files:
        file = request.files['file']
        if file and file.filename:
            # Validate file
            valid_file, file_error, secure_filename_result = validate_file_upload(file)
            if not valid_file:
                flash(file_error)
                return redirect(url_for('main.index'))
            
            # Create uploads directory
            upload_dir = os.path.join(current_app.root_path, 'uploads')
            if not os.path.exists(upload_dir):
                os.makedirs(upload_dir, exist_ok=True)
            
            # Save file with secure filename
            file_path = os.path.join(upload_dir, secure_filename_result)
            file.save(file_path)
            
            # Store relative path
            file_path = os.path.relpath(file_path, os.path.abspath(upload_dir))
    
    # Create document
    new_doc = Document(
        title=validated_title,
        content=sanitized_content,
        file_path=file_path,
        user_id=current_user.id
    )
    db.session.add(new_doc)
    db.session.commit()
    
    flash('Document uploaded successfully')
    return redirect(url_for('main.view_document', doc_id=new_doc.id))

@main.route('/download/<int:doc_id>')
@login_required
@document_access_required
def download_file(doc_id):
    document = Document.query.get_or_404(doc_id)
    
    # Check if document has an associated file
    if not document.file_path:
        flash('Este documento no tiene un archivo asociado', 'error')
        return redirect(url_for('main.view_document', doc_id=doc_id))
    
    # Secure file path construction - only allow files in uploads directory
    uploads_dir = os.path.join(current_app.root_path, 'uploads')
    safe_filename = secure_filename(os.path.basename(document.file_path))
    file_path = os.path.join(uploads_dir, safe_filename)
    
    # Ensure the file path is within the uploads directory
    if not os.path.abspath(file_path).startswith(os.path.abspath(uploads_dir)):
        current_app.logger.warning(f'Path traversal attempt blocked: {document.file_path}')
        abort(403, 'Acceso denegado')
    
    # Check if file exists
    if not os.path.isfile(file_path):
        flash('Archivo no encontrado', 'error')
        return redirect(url_for('main.view_document', doc_id=doc_id))
    
    # Send the file securely
    return send_file(
        file_path,
        as_attachment=True,
        download_name=safe_filename
    )

@main.route('/comment', methods=['POST'])
@login_required
def add_comment():
    document_id = request.form.get('document_id')
    content = request.form.get('content', '')
    
    # Validar que document_id esté presente
    if not document_id:
        flash('Error: Falta el document_id requerido', 'error')
        return redirect(url_for('main.index'))
    
    # Validate comment content
    valid_content, validated_content = validate_comment_content(content)
    if not valid_content:
        flash(validated_content, 'error')  # Error message
        return redirect(url_for('main.view_document', doc_id=document_id))
    
    # Verificar que el documento existe y el usuario tiene acceso
    document = Document.query.get_or_404(document_id)
    if not can_comment_on_document(current_user, document):
        flash('No tienes permiso para comentar en este documento', 'error')
        return redirect(url_for('main.index'))
    
    # Sanitize content for safe storage and display
    sanitized_content = sanitize_html_content(validated_content)
    
    # Create comment
    new_comment = Comment(
        content=sanitized_content,
        user_id=current_user.id,
        document_id=document_id
    )
    db.session.add(new_comment)
    db.session.commit()
    
    flash('Comentario agregado exitosamente', 'success')
    return redirect(url_for('main.view_document', doc_id=document_id))
