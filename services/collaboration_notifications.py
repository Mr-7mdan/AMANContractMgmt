from flask import render_template, current_app, request
from flask_mail import Message
from models import Settings, CollaborationAssignment, CollaborationEvent, Contract
from email_service import mail
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

def notify_collaboration_update(event):
    """Send email notification for collaboration update"""
    try:
        # Get enabled mail provider
        enabled_provider = Settings.get_value('mail_provider_enabled', '')
        sender_email = Settings.get_value(f'{enabled_provider}_username', '')
        
        if not sender_email:
            logger.error("No sender email configured")
            return False
            
        # Get collaboration and its assignments
        collaboration = event.collaboration
        assignments = CollaborationAssignment.query.filter_by(
            collaboration_id=collaboration.id,
            is_completed=False
        ).all()
        
        if not assignments:
            logger.info("No active assignments found for notification")
            return True
            
        # Use BASE_URL from config
        base_url = current_app.config['BASE_URL']
        logger.info(f"Using base URL for notifications: {base_url}")
        
        # Send individual email to each recipient
        for assignment in assignments:
            # Render email template with recipient info and proper base URL
            html = render_template(
                'emails/collaboration_notification.html',
                collaboration=collaboration,
                event=event,
                author=event.created_by or event.representative,
                recipient=assignment.representative,
                is_representative=True,
                assignment=assignment,
                base_url=base_url  # Pass base_url to template
            )
            
            # Create message
            msg = Message(
                subject=f'Update: {collaboration.title}',
                sender=sender_email,
                recipients=[assignment.representative.email],
                html=html
            )
            
            # Send email
            mail.send(msg)
            logger.info(f"Sent update notification to {assignment.representative.email}")
        
        return True
        
    except Exception as e:
        logger.error(f"Error sending collaboration update emails: {str(e)}", exc_info=True)
        return False

def verify_access_token(token, signature):
    """Verify legal access token and signature"""
    try:
        logger.info("=== Starting verify_access_token ===")
        logger.info(f"Checking token: {token}")
        logger.info(f"Checking signature: {signature}")
        
        # Find assignment with matching token and signature
        logger.info("Querying for active assignment...")
        assignment = CollaborationAssignment.query.filter_by(
            access_token=token,
            email_signature=signature,
            is_completed=False
        ).first()
        
        if assignment:
            logger.info(f"Found valid active assignment {assignment.id}")
            logger.info(f"Collaboration ID: {assignment.collaboration_id}")
            logger.info(f"Representative ID: {assignment.representative_id}")
            logger.info(f"Created at: {assignment.created_at}")
            return assignment, assignment.collaboration_id
            
        # Log all assignments for debugging
        logger.info("=== Checking all assignments ===")
        all_assignments = CollaborationAssignment.query.all()
        for a in all_assignments:
            logger.info(f"Assignment {a.id}:")
            logger.info(f"  Token: {a.access_token}")
            logger.info(f"  Signature: {a.email_signature}")
            logger.info(f"  Completed: {a.is_completed}")
            logger.info(f"  Collaboration: {a.collaboration_id}")
            logger.info(f"  Representative: {a.representative_id}")
            logger.info("---")
        
        # Check for completed assignments
        logger.info("Checking completed assignments...")
        completed = CollaborationAssignment.query.filter_by(
            access_token=token,
            email_signature=signature,
            is_completed=True
        ).first()
        
        if completed:
            logger.info(f"Found completed assignment {completed.id}")
            return completed, completed.collaboration_id
            
        # Check for token match only
        logger.info("Checking for token match only...")
        token_match = CollaborationAssignment.query.filter_by(
            access_token=token
        ).first()
        
        if token_match:
            logger.warning(f"Found token match but wrong signature")
            logger.warning(f"Expected: {token_match.email_signature}")
            logger.warning(f"Got: {signature}")
            return None, token_match.collaboration_id
            
        logger.warning("No matching assignment found")
        return None, None
        
    except Exception as e:
        logger.error(f"Error in verify_access_token: {str(e)}", exc_info=True)
        return None, None

def track_collaboration_activity(event):
    """Track collaboration activity for notifications"""
    try:
        # Add any activity tracking logic here
        pass
        
    except Exception as e:
        logger.error(f"Error tracking collaboration activity: {str(e)}")