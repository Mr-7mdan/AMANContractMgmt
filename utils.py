import os
from functools import wraps
from flask import current_app, request, abort, flash, render_template
from werkzeug.utils import secure_filename
from models import AuditLog, db
import logging
from flask_login import current_user

# Create a custom formatter that includes the user
class UserFormatter(logging.Formatter):
    def format(self, record):
        # Add username to the record if available
        if not hasattr(record, 'username'):
            try:
                record.username = current_user.username if not current_user.is_anonymous else 'anonymous'
            except Exception:
                record.username = 'system'
        
        return super().format(record)

# Setup logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO
)

# Create formatter
formatter = UserFormatter(
    '%(asctime)s - %(username)s - %(name)s - %(levelname)s - %(message)s'
)

# Get the root logger and set the formatter
for handler in logging.getLogger().handlers:
    handler.setFormatter(formatter)

logger = logging.getLogger(__name__)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

def save_file(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return filename, filepath
    return None, None

def log_audit(action, entity_type, entity_id, details, user=None):
    try:
        username = user or (current_user.username if not current_user.is_anonymous else 'system')
        audit = AuditLog(
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            details=details,
            user=username
        )
        db.session.add(audit)
        db.session.commit()
        logger.info(f"[{username}] {action} on {entity_type} {entity_id}: {details}")
    except Exception as e:
        logger.error(f"Error logging audit: {str(e)}")
        db.session.rollback()

def handle_error(e):
    """Generic error handler that logs errors"""
    username = current_user.username if not current_user.is_anonymous else 'anonymous'
    logger.error(f"[{username}] Error occurred: {str(e)}", exc_info=True)
    log_audit('error', 'system', None, f"Error: {str(e)}")
    flash("An error occurred. Please try again later.", "error")
    return render_template('errors/500.html'), 500

# Custom decorator for rate limiting
def rate_limit(limit=5, window=60):
    def decorator(f):
        from flask import session
        from time import time
        
        @wraps(f)
        def wrapped(*args, **kwargs):
            key = f'{f.__name__}_{request.remote_addr}'
            now = time()
            username = current_user.username if not current_user.is_anonymous else 'anonymous'
            
            # Get list of timestamps for this endpoint and IP
            requests = session.get(key, [])
            requests = [req for req in requests if req > now - window]
            
            if len(requests) >= limit:
                logger.warning(f"[{username}] Rate limit exceeded for {request.remote_addr} on {f.__name__}")
                log_audit('security', 'rate_limit', None, 
                         f'Rate limit exceeded for {request.remote_addr} on {f.__name__}')
                abort(429)
            
            requests.append(now)
            session[key] = requests
            return f(*args, **kwargs)
        return wrapped
    return decorator