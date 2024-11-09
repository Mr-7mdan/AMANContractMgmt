from flask import render_template, current_app, request
from flask_mail import Message
from models import Settings
from email_service import mail
import logging

logger = logging.getLogger(__name__)

def send_collaboration_email(collaboration, assignment):
    """Send collaboration request email to legal representative"""
    try:
        # Get enabled mail provider
        enabled_provider = Settings.get_value('mail_provider_enabled', '')
        sender_email = Settings.get_value(f'{enabled_provider}_username', '')
        
        if not sender_email:
            logger.error("No sender email configured")
            return False
            
        logger.info(f"Sending collaboration email to {assignment.representative.email}")
        logger.info(f"Using sender email: {sender_email}")
        
        # Use BASE_URL from config instead of request.url_root
        base_url = current_app.config['BASE_URL']
        access_url = f"{base_url}/legal/access/{assignment.access_token}?sig={assignment.email_signature}"
        
        logger.info(f"Generated access URL: {access_url}")
        logger.info(f"Using base URL: {base_url}")
        
        # Render email template
        html = render_template(
            'emails/collaboration_request.html',
            collaboration=collaboration,
            representative=assignment.representative,
            access_url=access_url
        )
        
        # Create message
        msg = Message(
            subject=f'Legal Collaboration Request: {collaboration.title}',
            sender=sender_email,
            recipients=[assignment.representative.email],
            html=html
        )
        
        # Send email
        mail.send(msg)
        logger.info(f"Successfully sent collaboration email to {assignment.representative.email}")
        return True
        
    except Exception as e:
        logger.error(f"Error sending collaboration email: {str(e)}", exc_info=True)
        return False