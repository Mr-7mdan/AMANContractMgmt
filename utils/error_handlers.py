from flask import flash, redirect, url_for
import logging
from werkzeug.utils import secure_filename
import os

logger = logging.getLogger(__name__)

def handle_error(e):
    """Generic error handler"""
    logger.error(f"Error occurred: {str(e)}", exc_info=True)
    flash('An error occurred. Please try again.', 'error')
    return redirect(url_for('dashboard'))

def rate_limit(max_requests=100, window=60):
    """Rate limiting decorator"""
    def decorator(f):
        def wrapped(*args, **kwargs):
            # Implement rate limiting logic here
            return f(*args, **kwargs)
        return wrapped
    return decorator

def save_file(file, upload_folder):
    """Save uploaded file and return filename"""
    try:
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(upload_folder, filename))
            return filename
    except Exception as e:
        logger.error(f"Error saving file: {str(e)}", exc_info=True)
        return None 