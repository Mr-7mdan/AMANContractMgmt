from flask import current_app
from models import AuditLog, db
from flask_login import current_user
import logging

logger = logging.getLogger(__name__)

def log_audit(action, entity_type, entity_id, details):
    """Log an audit event"""
    try:
        audit = AuditLog(
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            details=details,
            user=current_user.username if current_user and current_user.is_authenticated else 'system'
        )
        db.session.add(audit)
        db.session.commit()
        logger.info(f"Audit log created: {action} {entity_type} {entity_id}")
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating audit log: {str(e)}", exc_info=True) 