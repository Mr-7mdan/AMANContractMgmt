from functools import wraps
from flask import request, redirect, url_for, current_app
import jwt
from datetime import datetime, timedelta

def create_access_token(assignment_id, representative_id, expiry_minutes=60):
    """Create a JWT token for legal access"""
    payload = {
        'assignment_id': assignment_id,
        'representative_id': representative_id,
        'exp': datetime.utcnow() + timedelta(minutes=expiry_minutes)
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')

def verify_access_token(token, signature):
    """Verify the access token and signature for legal representative access"""
    try:
        logger.info(f"Verifying token: {token} with signature: {signature}")
        
        # First try to find by exact token/signature
        assignment = CollaborationAssignment.query.filter_by(
            access_token=token,
            email_signature=signature
        ).first()
        
        if not assignment:
            # Try to find by revoked token
            assignment = CollaborationAssignment.query.filter(
                CollaborationAssignment.access_token.like(f'REVOKED_{token}%')
            ).first()
            
        if not assignment:
            logger.info(f"No assignment found for token: {token}")
            return None, None
            
        if assignment.is_completed:
            logger.info(f"Assignment {assignment.id} is already completed")
            return None, assignment.collaboration_id
            
        # Check if token is expired
        if assignment.created_at < datetime.utcnow() - timedelta(hours=24):
            logger.info(f"Access token expired for assignment {assignment.id}")
            return None, assignment.collaboration_id
            
        return assignment, None
        
    except Exception as e:
        logger.error(f"Error verifying access token: {str(e)}", exc_info=True)
        return None, None

def legal_access_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.args.get('token')
        signature = request.args.get('sig')
        
        if not token or not signature:
            return redirect(url_for('legal_error', error_type='invalid'))
            
        # Verify JWT token
        payload = verify_access_token(token, signature)
        if not payload:
            return redirect(url_for('legal_error', error_type='expired'))
            
        # Verify signature matches assignment
        from models import CollaborationAssignment
        assignment = CollaborationAssignment.query.get(payload['assignment_id'])
        if not assignment or assignment.email_signature != signature:
            return redirect(url_for('legal_error', error_type='invalid'))
            
        # Check if assignment is completed
        if assignment.is_completed:
            return redirect(url_for('legal_error', error_type='expired'))
            
        # Add assignment to request context
        request.legal_assignment = assignment
        return f(*args, **kwargs)
        
    return decorated_function 