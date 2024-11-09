from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, send_from_directory, make_response, session, abort, current_app
from sqlalchemy import func
from config import Config
from werkzeug.urls import url_parse
from flask_migrate import Migrate
from functools import wraps
import socket
from contextlib import closing
import time
import secrets
import hashlib
from datetime import datetime, timedelta
import pytz
from urllib.parse import urlparse


# Create Flask app first
app = Flask(__name__)
app.config.from_object(Config)

# Set default SERVER_NAME to None to prevent KeyError
app.config['SERVER_NAME'] = None

# Initialize SQLAlchemy without binding to app yet
from models import create_default_admin, db
db.init_app(app)

# After db.init_app(app), add:
migrate = Migrate(app, db)

# Now import the models
from models import User, Contract, Attachment, NotificationHistory, AuditLog, Settings, LegalOffice, LegalRepresentative, Collaboration, CollaborationEvent, CollaborationAssignment, UserType  # Add UserType to imports
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
import os
from werkzeug.utils import secure_filename
import json
from datetime import date
from scheduler import init_scheduler, scheduler
from email_service import setup_mail, mail, send_contract_notifications, send_periodic_report
from utils import log_audit, handle_error, rate_limit, save_file
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_mail import Message
import logging
import socket
from contextlib import closing

# Add this import near the top of app.py with other imports
from utils.notifications import get_collaboration_notifications

# Add this import near the top with other imports
from services.collaboration_notifications import notify_collaboration_update, track_collaboration_activity, verify_access_token
from collaboration_service import send_collaboration_email  # Add this line
# Add these imports at the top
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta

# Add these imports at the top
from utils.tokens import generate_access_token, generate_email_signature  # Add this import

# Create logs directory if it doesn't exist
if not os.path.exists('logs'):
    os.makedirs('logs')

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/app.log'),
        logging.StreamHandler()  # This will also print to console
    ]
)
logger = logging.getLogger(__name__)

# Initialize the email notification scheduler
email_scheduler = BackgroundScheduler()
email_scheduler.start()

# Add this function to get the local IP address
def get_local_ip():
    try:
        # Get the local machine's IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Add security headers middleware
@app.after_request
def add_security_headers(response):
    for header, value in app.config['SECURITY_HEADERS'].items():
        response.headers[header] = value
    return response

# Add error handlers
@app.errorhandler(404)
def not_found_error(error):
    log_audit('error', 'system', None, f"404 error: {request.url}")
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return handle_error(error)

# Update the user loader to use the new SQLAlchemy 2.0 style
@login_manager.user_loader
def load_user(user_id):
    # Replace query.get() with db.session.get()
    return db.session.get(User, int(user_id))

# Add these constants at the top of the file
SESSION_TIMEOUT = 6000  # 10 minutes in seconds
LAST_ACTIVITY_KEY = 'last_activity'

@app.before_request
def check_session_timeout():
    """Check for session timeout before each request"""
    if request.endpoint == 'static':
        return
        
    if current_user.is_authenticated:
        # Get last activity time
        last_activity = session.get(LAST_ACTIVITY_KEY)
        
        if last_activity is not None:
            # Convert to datetime if stored as string
            if isinstance(last_activity, str):
                last_activity = datetime.fromisoformat(last_activity)
                
            # Make sure both datetimes are naive for comparison
            now = datetime.utcnow()
            if last_activity.tzinfo:
                last_activity = last_activity.replace(tzinfo=None)
                
            # Check if session has timed out
            if now - last_activity > timedelta(seconds=SESSION_TIMEOUT):
                # Log the timeout
                logger.info(f"Session timeout for user {current_user.username}")
                
                # Clear session
                logout_user()
                session.clear()
                
                # Redirect to timeout page
                if request.endpoint != 'session_timeout':
                    return redirect(url_for('session_timeout'))
                    
        # Update last activity time
        session[LAST_ACTIVITY_KEY] = datetime.utcnow()

@app.route('/session-timeout')
def session_timeout():
    """Handle session timeout"""
    return render_template('session_timeout.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login"""
    try:
        # If user is already logged in, redirect to dashboard
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
            
        logger.info(f"Login attempt - Method: {request.method}")
        
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            next_page = request.form.get('next') or request.args.get('next')
            
            logger.info(f"Login attempt for username: {username}")
            logger.info(f"Next page: {next_page}")
            
            user = User.query.filter_by(username=username).first()
            
            if user:
                logger.info(f"User found with type: {user.user_type}")
                logger.info(f"Password hash: {user.password_hash}")
                
                is_valid = user.check_password(password)
                logger.info(f"Password valid: {is_valid}")
                
                if is_valid:
                    logger.info(f"Password correct for user {username} with type {user.user_type}")
                    login_user(user)
                    
                    # Log the login
                    log_audit('login', 'user', user.id, f"User logged in")
                    
                    # Validate and use next parameter
                    if next_page and url_parse(next_page).netloc == '':
                        logger.info(f"Redirecting to next page: {next_page}")
                        return redirect(next_page)
                        
                    logger.info(f"Redirecting to dashboard")
                    return redirect(url_for('dashboard'))
                    
                else:
                    logger.warning(f"Invalid password for user {username}")
                    flash('Invalid username or password', 'error')
            else:
                logger.warning(f"User not found: {username}")
                flash('Invalid username or password', 'error')
                
        # For GET requests or failed login attempts, get next parameter from query string
        next_page = request.args.get('next')
        logger.info(f"Rendering login page with next: {next_page}")
        return render_template('login.html', next=next_page)
        
    except Exception as e:
        logger.error(f"Error in login: {str(e)}", exc_info=True)
        flash('Error logging in', 'error')
        return render_template('login.html')

def is_safe_url(target):
    """Check if URL is safe for redirects"""
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

@app.route('/logout')
@login_required
def logout():
    logger.info(f"Logout request from user: {current_user.username}")
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard view"""
    try:
        # Get page numbers from query params
        contracts_page = request.args.get('contracts_page', 1, type=int)
        collabs_page = request.args.get('collabs_page', 1, type=int)
        notifs_page = request.args.get('notifs_page', 1, type=int)
        
        # Get active contracts with pagination
        contracts = Contract.query.filter_by(is_active=True)\
            .order_by(Contract.expiry_date)\
            .paginate(page=contracts_page, per_page=10)
        
        # Get open collaborations based on user type and role
        collab_query = Collaboration.query.filter_by(status='open')
        
        if not current_user.is_admin:
            # For legal representatives
            if current_user.user_type == UserType.LEGAL_REP.value:
                # Get the legal representative record for this user
                representative = LegalRepresentative.query.filter_by(email=current_user.email).first()
                if representative:
                    # Get collaborations assigned to this representative
                    assigned_collabs = Collaboration.query\
                        .join(CollaborationAssignment)\
                        .filter(
                            CollaborationAssignment.representative_id == representative.id,
                            Collaboration.status == 'open'
                        )
                    collab_query = assigned_collabs
                    
            else:
                # For standard users, show collaborations they created
                created_collabs = Collaboration.query.filter_by(
                    created_by_id=current_user.id,
                    status='open'
                )
                collab_query = created_collabs
        else:
            # For admin users, show all collaborations
            created_collabs = Collaboration.query.filter_by(
                status='open'
            )
            collab_query = created_collabs

        # Apply ordering and pagination
        collaborations = collab_query.order_by(Collaboration.updated_at.desc()).all()
        
        # Get notification history for admins
        if current_user.is_admin:
            notifications = NotificationHistory.query\
                .order_by(NotificationHistory.created_at.desc())\
                .paginate(page=notifs_page, per_page=5)
        else:
            notifications = None
            
        # Get legal offices for the modal
        legal_offices = LegalOffice.query.filter_by(is_active=True).all()
        
        logger.info(f"Dashboard loaded for user {current_user.username} (type: {current_user.user_type})")
        logger.info(f"Found {len(collaborations)} open collaborations")
        
        return render_template('dashboard.html',
                             contracts=contracts,
                             collaborations=collaborations,
                             notifications=notifications,
                             legal_offices=legal_offices)
                             
    except Exception as e:
        logger.error(f"Error in dashboard: {str(e)}", exc_info=True)
        flash('Error loading dashboard', 'error')
        return redirect(url_for('login'))

@app.route('/contract/new', methods=['GET'])
@login_required
def new_contract():
    logger.info("New contract form requested")
    return render_template('contract_form.html', contract=None, title="New Contract")

@app.route('/contract/<int:contract_id>/edit', methods=['GET'])
@login_required
def edit_contract(contract_id):
    logger.info(f"Edit contract form requested for contract ID: {contract_id}")
    contract = db.session.get(Contract, contract_id)
    if not contract:
        flash('Contract not found', 'error')
        return redirect(url_for('dashboard'))
    return render_template('contract_form.html', contract=contract, title="Edit Contract")

@app.route('/contract/save', methods=['POST'])
@login_required
def save_contract():
    """Save contract"""
    try:
        logger.info("Saving contract")
        # Get contract_id from both form data and query parameters
        contract_id = request.form.get('contract_id') or request.args.get('contract_id')
        logger.info(f"Contract ID from request: {contract_id}")
        
        # Log form data for debugging
        logger.info(f"Form data: {request.form}")
        
        if contract_id:
            # Update existing contract
            contract = Contract.query.get_or_404(int(contract_id))
            logger.info(f"Updating existing contract {contract_id}")
        else:
            # Add new contract
            contract = Contract()
            logger.info("Creating new contract")
            
        # Update contract fields with validation
        contract.name = request.form.get('name')
        contract.party_name = request.form.get('party_name')
        contract.signing_date = datetime.strptime(request.form.get('signing_date'), '%Y-%m-%d').date()
        contract.validity_days = int(request.form.get('validity_days'))
        
        # Set notify_period with default if not provided
        notify_period = request.form.get('notify_period')
        if not notify_period:
            notify_period = 'One Week'  # Default value
        contract.notify_period = notify_period
        
        # Calculate expiry date
        contract.expiry_date = contract.signing_date + timedelta(days=contract.validity_days)
        contract.is_active = True
        
        # Only add to session if it's a new contract
        if not contract_id:
            db.session.add(contract)
        
        db.session.flush()
        logger.info(f"Contract ID after flush: {contract.id}")

        # Handle attachments
        if 'attachments' in request.files:
            files = request.files.getlist('attachments')
            for file in files:
                if file and file.filename and allowed_file(file.filename):
                    # Generate stored filename
                    file_ext = os.path.splitext(file.filename)[1]
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    stored_filename = f"contract_{contract.id}_{timestamp}{file_ext}"
                    
                    # Create directory if it doesn't exist
                    upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'contracts')
                    os.makedirs(upload_dir, exist_ok=True)
                    
                    # Save file
                    file_path = os.path.join(upload_dir, stored_filename)
                    file.save(file_path)
                    
                    # Create attachment record
                    attachment = Attachment(
                        contract_id=contract.id,
                        original_filename=file.filename,
                        stored_filename=stored_filename,
                        file_size=os.path.getsize(file_path),
                        mime_type=file.content_type
                    )
                    db.session.add(attachment)

        # Commit all changes
        db.session.commit()
        logger.info(f"Final contract ID: {contract.id}")
        
        # Log audit
        log_audit(
            'create' if not contract_id else 'update',
            'contract',
            contract.id,
            f"{'Created' if not contract_id else 'Updated'} contract: {contract.name}"
        )
        
        flash(f"Contract {'created' if not contract_id else 'updated'} successfully", 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error saving contract: {str(e)}")
        flash("Error saving contract", 'error')
        return redirect(url_for('dashboard'))

@app.route('/contract/<int:contract_id>/notify-period', methods=['PUT'])
@login_required
def update_notify_period(contract_id):
    try:
        contract = db.session.get(Contract, contract_id)
        if not contract:
            logger.error(f"Contract not found: {contract_id}")
            return 'Contract not found', 404
        
        # Get the new period from the request data
        new_period = request.form.get('notify_period')
        logger.info(f"Received notify period update request: {new_period} for contract {contract_id}")
        
        if new_period not in ['One Week', 'Two Weeks', 'One Month', 'Two Months']:
            logger.error(f"Invalid notify period value: {new_period}")
            return 'Invalid notify period', 400
            
        contract.notify_period = new_period
        db.session.commit()
        
        logger.info(f"Updated notify period for contract {contract_id} to {new_period}")
        log_audit('update', 'contract', contract.id, f'Updated notify period to {new_period}')
        
        # Return success message that will be shown in a toast
        return {
            'message': f'Notification period updated to {new_period}',
            'type': 'success'
        }
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating notify period: {str(e)}", exc_info=True)
        return {
            'message': f'Error updating notification period: {str(e)}',
            'type': 'error'
        }, 500

@app.route('/contract/<int:contract_id>/delete', methods=['POST'])
@login_required
def delete_contract(contract_id):
    """Delete contract"""
    try:
        contract = Contract.query.get_or_404(contract_id)
        logger.info(f"Deleting contract: {contract.name} (ID: {contract.id})")
        
        # Delete associated attachments first
        for attachment in contract.attachments:
            # Delete physical file
            if attachment.stored_filename:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'contracts', attachment.stored_filename)
                if os.path.exists(file_path):
                    os.remove(file_path)
                    logger.info(f"Deleted file: {file_path}")
            
            # Delete attachment record
            db.session.delete(attachment)
            logger.info(f"Deleted attachment record: {attachment.original_filename}")
        
        # Delete contract
        db.session.delete(contract)
        db.session.commit()
        
        # Log the deletion
        log_audit('delete', 'contract', contract_id, f"Deleted contract: {contract.name}")
        logger.info(f"Successfully deleted contract {contract_id}")
        
        return jsonify({
            'success': True,
            'message': 'Contract deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting contract: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/attachments/<int:contract_id>')
@login_required
def view_attachments(contract_id):
    """View contract attachments"""
    try:
        contract = Contract.query.get_or_404(contract_id)
        return render_template('attachments.html', contract=contract)
    except Exception as e:
        logger.error(f"Error viewing attachments: {str(e)}")
        flash('Error viewing attachments', 'error')
        return redirect(url_for('dashboard'))

@app.route('/preview/<int:attachment_id>')
@login_required
def preview_pdf(attachment_id):
    attachment = Attachment.query.get_or_404(attachment_id)
    if not attachment:
        abort(404)
    return send_file(
        attachment.file_path,
        mimetype='application/pdf'
    )

@app.route('/attachment/<int:attachment_id>/download')
@login_required
def attachment_download(attachment_id):  # Changed function name to match endpoint
    """Download attachment file"""
    try:
        logger.info(f"Downloading attachment {attachment_id}")
        attachment = Attachment.query.get_or_404(attachment_id)
        
        # Get the correct directory based on attachment type
        if attachment.contract_id:
            upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'contracts')
        else:
            upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'chatFiles')
        
        file_path = os.path.join(upload_dir, attachment.stored_filename)
        logger.info(f"File path: {file_path}")
        
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            flash('The requested file could not be found', 'error')
            return redirect(url_for('dashboard'))
            
        logger.info(f"Sending file: {attachment.original_filename}")
        return send_from_directory(
            upload_dir,
            attachment.stored_filename,
            as_attachment=True,
            download_name=attachment.original_filename
        )
        
    except Exception as e:
        logger.error(f"Error downloading attachment: {str(e)}")
        flash('Error downloading file', 'error')
        return redirect(url_for('dashboard'))

@app.route('/attachment/<int:attachment_id>/delete', methods=['POST'])
@login_required
def delete_attachment(attachment_id):
    """Delete attachment"""
    try:
        attachment = Attachment.query.get_or_404(attachment_id)
        
        # Get file path
        if attachment.contract_id:
            upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'contracts')
        else:
            upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'chatFiles')
            
        file_path = os.path.join(upload_dir, attachment.stored_filename)
        
        # Delete file if exists
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Delete record
        db.session.delete(attachment)
        db.session.commit()
        
        logger.info(f"Deleted attachment: {attachment.original_filename}")
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting attachment: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Additional routes will be added for contract management and notifications 

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.username != 'aman':
            flash('You must be an admin to access this page.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Update the admin-only routes
@app.route('/users')
@login_required
@admin_required
def users():
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/settings')
@login_required
@admin_required
def settings():
    from models import Settings, MAIL_PROVIDERS
    
    email_settings = {
        'mail_provider': Settings.get_value('mail_provider', 'outlook'),
        'mail_provider_enabled': Settings.get_value('mail_provider_enabled', 'outlook'),
        # Gmail settings
        'gmail_username': Settings.get_value('gmail_username', ''),
        # Outlook settings
        'outlook_username': Settings.get_value('outlook_username', ''),
        # Exchange settings
        'exchange_username': Settings.get_value('exchange_username', ''),
        'exchange_server': Settings.get_value('exchange_server', ''),
        # Add MAIL_PROVIDERS dictionary
        'MAIL_PROVIDERS': MAIL_PROVIDERS
    }
    return render_template('settings.html', settings=email_settings)

@app.route('/notification-settings')
@login_required
@admin_required
def notification_settings():
    settings = {
        'notification_emails': Settings.get_value('notification_emails', 'contracts@aman.ps'),
        'expiry_notifications_enabled': Settings.get_value('expiry_notifications_enabled', 'true'),
        'periodic_notifications_enabled': Settings.get_value('periodic_notifications_enabled', 'false'),
        'notification_periods': Settings.get_value('notification_periods', '["One Week"]'),
        'report_frequency': Settings.get_value('report_frequency', 'monthly'),
        'report_day': Settings.get_value('report_day', '1')
    }
    return render_template('notification_settings.html', settings=settings)

@app.route('/test-notifications', methods=['POST'])
@login_required
@admin_required
def test_notifications():
    try:
        logger.info("Testing notification service")
        message, success = send_contract_notifications()
        
        # Flash message will be included in the returned HTML
        if success:
            flash(message, 'success')
        else:
            flash(message, 'info')
            
        logger.info(f"Notification test result: {message}")
        
        # Get updated notifications
        notifications = NotificationHistory.query.order_by(NotificationHistory.sent_at.desc()).all()
        
        # Return the updated notification history section
        return render_template('_notification_history.html', notifications=notifications)
        
    except Exception as e:
        error_msg = f'Error testing notifications: {str(e)}'
        logger.error(error_msg, exc_info=True)
        flash(error_msg, 'error')
        return error_msg, 500

# Add this route to handle notification viewing
@app.route('/notification/<int:notification_id>')
@login_required
def view_notification(notification_id):
    try:
        notification = NotificationHistory.query.get_or_404(notification_id)
        return render_template('notification_details.html', notification=notification)
    except Exception as e:
        logger.error(f"Error viewing notification {notification_id}: {str(e)}", exc_info=True)
        flash(f"Error viewing notification: {str(e)}", 'error')
        return redirect(url_for('dashboard'))

@app.template_filter('from_json')
def from_json(value):
    try:
        return json.loads(value) if value else []
    except:
        return []

@app.route('/notifications/clear', methods=['DELETE'])
@login_required
@admin_required
def clear_notifications():
    """Clear all notifications"""
    try:
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
            
        # Delete all notifications
        NotificationHistory.query.delete()
        db.session.commit()
        
        logger.info("All notifications cleared successfully")
        return jsonify({'success': True, 'message': 'All notifications cleared successfully'})
        
    except Exception as e:
        logger.error(f"Error clearing notifications: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to clear notifications'}), 500

@app.route('/users/new', methods=['GET', 'POST'])
@login_required
@admin_required
def new_user():
    """Create new user"""
    try:
        # Check if mail is configured
        mail_configured = check_mail_configuration()
        logger.info(f"Mail configuration status: {mail_configured}")
        
        if request.method == 'POST':
            # Check if user wants to send password email
            send_password_email = request.form.get('send_password_email') == 'on'
            
            if send_password_email and not mail_configured:
                flash('Cannot send password email. Email provider not configured.', 'error')
                return redirect(url_for('users'))
            
            # Create user
            user = User(
                name=request.form['name'],
                username=request.form['username'],
                email=request.form['email'],
                user_type=request.form['user_type']
            )
            
            if send_password_email:
                # Generate password setup token
                token = secrets.token_urlsafe(32)
                user.password_token = token
                user.token_expiry = datetime.utcnow() + timedelta(hours=24)
                
                # Set temporary password
                temp_password = secrets.token_hex(16)
                user.set_password(temp_password)
                
                # Send password setup email
                setup_url = url_for('set_password', token=token, _external=True)
                html = render_template('emails/set_password.html',
                                    name=user.name,
                                    username=user.username,
                                    setup_url=setup_url)
                
                # Get sender email from settings
                enabled_provider = Settings.get_value('mail_provider_enabled', 'outlook')
                sender_email = Settings.get_value(f'{enabled_provider}_username', '')
                
                msg = Message(
                    subject='Set Your Password - Aman Contracts Management System',
                    sender=sender_email,
                    recipients=[user.email],
                    html=html
                )
                mail.send(msg)
            else:
                # Set password directly
                user.set_password(request.form['password'])
            
            db.session.add(user)
            db.session.commit()
            
            log_audit('create', 'user', user.id, f"Created user: {user.username}")
            flash('User added successfully', 'success')
            return redirect(url_for('users'))
            
        # Pass the user types as choices
        user_types = UserType.choices()
        logger.info(f"Available user types: {user_types}")
        
        return render_template('user_form.html', 
                             title='New User',
                             user=None,
                             mail_configured=mail_configured,
                             user_types=user_types)
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating user: {str(e)}")
        flash('Error creating user', 'error')
        return redirect(url_for('users'))

@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    """Edit existing user"""
    user = User.query.get_or_404(user_id)
    # Pass UserType enum to template
    return render_template('user_form.html', title='Edit User', user=user, UserType=UserType)

@app.route('/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    if user_id == current_user.id:
        return 'Cannot delete yourself', 400
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return '', 204

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        if not current_user.check_password(request.form['current_password']):
            flash('Current password is incorrect', 'error')
            return redirect(url_for('change_password'))
            
        if request.form['new_password'] != request.form['confirm_password']:
            flash('New passwords do not match', 'error')
            return redirect(url_for('change_password'))
            
        current_user.set_password(request.form['new_password'])
        db.session.commit()
        flash('Password changed successfully', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('change_password.html')

@app.route('/contract/<int:contract_id>/view')
@login_required
def view_contract(contract_id):
    """View contract details"""
    try:
        # Get contract by ID
        contract = Contract.query.get_or_404(contract_id)
        
        # Get contract extensions
        extensions = []  # You can add extension logic here if needed
        logger.info(f"Extensions for contract {contract_id}: {extensions}")
        
        return render_template('view_contract.html', contract=contract)
        
    except Exception as e:
        logger.error(f"Error viewing contract {contract_id}: {str(e)}")
        flash('Error viewing contract', 'error')
        return redirect(url_for('dashboard'))

@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user_with_confirmation(user_id):
    try:
        # Get the admin password from the request
        data = request.get_json()
        admin_password = data.get('admin_password')
        
        # Verify admin credentials
        admin = User.query.filter_by(username='aman').first()
        if not admin or not admin.check_password(admin_password):
            return "Invalid admin password", 401
        
        # Check if trying to delete admin user
        if user_id == admin.id:
            return "Cannot delete admin user", 403
            
        # Get and delete the user
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        
        flash(f'User {user.name} deleted successfully', 'success')
        log_audit('delete', 'user', user_id, f'Deleted user: {user.name}')
        return '', 204
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting user: {str(e)}", exc_info=True)
        return str(e), 500

@app.route('/notification-settings/toggle/<type>', methods=['POST'])
@login_required
@admin_required
def toggle_notification(type):
    """Toggle notification settings"""
    try:
        # Get the value from the toggle switch
        enabled = request.form.get('checked') == 'true'
        setting_key = f'{type}_notifications_enabled'
        
        # Save the setting
        Settings.set_value(setting_key, str(enabled).lower())
        
        # Update scheduler job
        from scheduler import update_job_schedule
        job_id = 'expiry_check' if type == 'expiry' else 'periodic_report'
        update_job_schedule(job_id, enabled)
        
        # Log the change with a better description
        setting = Settings.query.filter_by(key=setting_key).first()
        log_audit('update', 'notification_settings', setting.id if setting else None, 
                 f'{"Enabled" if enabled else "Disabled"} {type} notifications')
        
        return '', 204
    except Exception as e:
        logger.error(f"Error toggling {type} notifications: {str(e)}", exc_info=True)
        return str(e), 500

@app.route('/notification-settings/expiry', methods=['POST'])
@login_required
def save_expiry_settings():
    periods = request.form.getlist('notification_periods')
    Settings.set_value('notification_periods', json.dumps(periods))
    flash('Expiry notification settings saved', 'success')
    return '', 204

@app.route('/notification-settings/periodic', methods=['POST'])
@login_required
def save_periodic_settings():
    frequency = request.form.get('report_frequency')
    day = request.form.get('report_day')
    Settings.set_value('report_frequency', frequency)
    Settings.set_value('report_day', day)
    flash('Periodic report settings saved', 'success')
    return '', 204

@app.route('/test-expiry-notification', methods=['POST'])
@login_required
def test_expiry_notification():
    message, success = send_contract_notifications()
    return render_template('_test_result.html', 
                         success=success, 
                         message=message)

@app.route('/test-periodic-report', methods=['POST'])
@login_required
def test_periodic_report():
    message, success = send_periodic_report()
    return render_template('_test_result.html', 
                         success=success, 
                         message=message)

@app.route('/scheduler/test', methods=['POST'])
@login_required
def test_scheduler_job():
    """Test run a scheduled job"""
    try:
        # Check if user is admin
        logger.info(f"User {current_user.username} (type: {current_user.user_type}) attempting to test scheduler job")
        
        if current_user.user_type != 'Admin':
            logger.warning(f"Non-admin user {current_user.username} attempted to access scheduler test")
            return jsonify({
                'success': False,
                'message': 'You must be admin to access this page'
            }), 403
            
        job_type = request.args.get('type')
        logger.info(f"Testing scheduler job: {job_type}")
        
        # Import the notification functions
        from scheduler import send_contract_notifications, send_periodic_report  # Changed import
        
        if job_type == 'expiry_check':
            logger.info("Starting contract notifications test")
            with app.app_context():  # Add app context
                message, success = send_contract_notifications()
            logger.info(f"Contract notifications test result - Success: {success}, Message: {message}")
            
            if success:
                return jsonify({
                    'success': True,
                    'message': 'Contract notifications sent successfully'
                })
            else:
                return jsonify({
                    'success': False,
                    'message': message or 'Error sending contract notifications'
                })
            
        elif job_type == 'periodic_report':
            logger.info("Starting periodic report test")
            with app.app_context():  # Add app context
                message, success = send_periodic_report()
            logger.info(f"Periodic report test result - Success: {success}, Message: {message}")
            
            if success:
                return jsonify({
                    'success': True,
                    'message': 'Periodic report sent successfully'
                })
            else:
                return jsonify({
                    'success': False,
                    'message': message or 'Error sending periodic report'
                })
            
        else:
            logger.error(f"Invalid job type: {job_type}")
            return jsonify({
                'success': False,
                'message': f'Invalid job type: {job_type}'
            }), 400
            
    except Exception as e:
        error_msg = f"Error testing scheduler job: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return jsonify({
            'success': False,
            'message': error_msg
        }), 500

# Add this function near the top of the file with other utility functions
def is_port_in_use(port):
    """Check if a port is in use"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            # Try to bind to the port
            s.bind(('0.0.0.0', port))
            # If successful, port is free
            return False
        except OSError:
            # If we get an error, port is in use
            return True

def find_free_port(start_port=5000, max_attempts=100):
    """Find a free port starting from start_port"""
    for port in range(start_port, start_port + max_attempts):
        if not is_port_in_use(port):
            return port
    raise RuntimeError(f"Could not find a free port after {max_attempts} attempts")

# Add this function near the top with other initialization functions
def init_settings():
    """Initialize default settings if they don't exist"""
    # Get the provider and username
    provider = Settings.get_value('mail_provider', 'outlook')
    username = Settings.get_value(f'{provider}_username', '')
    
    default_settings = {
        'notification_emails': username or 'mhamdan@aman.ps',  # Use authenticated email
        'sender_email': username or 'mhamdan@aman.ps',  # Use authenticated email
        'smtp_server': 'smtp.office365.com',  # Default to Outlook
        'smtp_port': '587',
        'smtp_use_tls': 'true',
        'smtp_username': username,
        'expiry_notifications_enabled': 'true',
        'periodic_notifications_enabled': 'false',
        'notification_periods': '["One Week"]',
        'report_frequency': 'monthly',
        'report_day': '1'
    }
    
    for key, value in default_settings.items():
        if not Settings.query.filter_by(key=key).first():
            setting = Settings(key=key, value=value)
            db.session.add(setting)
            logger.info(f"Created default setting: {key}")
    
    try:
        db.session.commit()
        logger.info("Settings initialized successfully")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error initializing settings: {str(e)}", exc_info=True)

@app.route('/settings/email', methods=['POST'])
@login_required
@admin_required
def save_email_settings():
    """Save email provider settings"""
    try:
        # Get the selected provider
        provider = request.form.get('mail_provider')
        if not provider:
            raise ValueError("No mail provider specified")

        logger.info(f"Saving settings for provider: {provider}")
        
        # Save provider-specific settings
        if provider == 'gmail':
            username = request.form.get('gmail_username', '').strip()
            password = request.form.get('gmail_password', '').strip()
            
            if username:
                Settings.set_value('gmail_username', username)
                logger.info(f"Saved Gmail username: {username}")
            
            if password:  # Only update password if provided
                Settings.set_value('gmail_password', password)
                logger.info("Gmail password was provided and saved")
            else:
                logger.warning("No Gmail password provided in form")
                
        elif provider == 'outlook':
            username = request.form.get('outlook_username', '').strip()
            password = request.form.get('outlook_password', '').strip()
            
            if username:
                Settings.set_value('outlook_username', username)
            if password:
                Settings.set_value('outlook_password', password)
            
        elif provider == 'exchange':
            username = request.form.get('exchange_username', '').strip()
            password = request.form.get('exchange_password', '').strip()
            server = request.form.get('exchange_server', '').strip()
            
            if username:
                Settings.set_value('exchange_username', username)
            if password:
                Settings.set_value('exchange_password', password)
            if server:
                Settings.set_value('exchange_server', server)
        else:
            raise ValueError(f"Invalid provider: {provider}")

        # Save general provider settings
        Settings.set_value('mail_provider', provider)
        Settings.set_value('mail_provider_enabled', provider)
        
        # Verify settings were saved
        verify_username = Settings.get_value(f'{provider}_username')
        verify_password = Settings.get_value(f'{provider}_password')
        logger.info(f"Verification - Username saved: {bool(verify_username)}, Password saved: {bool(verify_password)}")
        
        # Reconfigure mail
        setup_mail(app)
        
        # Log the audit
        log_audit('update', 'settings', None, f'Updated email settings for {provider}')
        
        return jsonify({
            'success': True,
            'message': f'{provider.title()} settings saved successfully'
        })
        
    except Exception as e:
        error_msg = f"Error saving email settings: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return jsonify({
            'success': False,
            'message': error_msg
        }), 500

# Add this helper function to debug settings
@app.route('/settings/debug', methods=['GET'])
@login_required
@admin_required
def debug_settings():
    """Debug endpoint to view all settings"""
    try:
        all_settings = {
            'mail_provider': Settings.get_value('mail_provider'),
            'mail_provider_enabled': Settings.get_value('mail_provider_enabled'),
            'outlook_username': Settings.get_value('outlook_username'),
            'gmail_username': Settings.get_value('gmail_username'),
            'exchange_username': Settings.get_value('exchange_username'),
            'exchange_server': Settings.get_value('exchange_server'),
            'notification_emails': Settings.get_value('notification_emails'),
            'expiry_notifications_enabled': Settings.get_value('expiry_notifications_enabled'),
            'periodic_notifications_enabled': Settings.get_value('periodic_notifications_enabled')
        }
        return jsonify(all_settings)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/settings/test-email', methods=['POST'])
@login_required
@admin_required
def test_email_settings():
    """Test email settings by sending a test email"""
    try:
        provider = request.form.get('mail_provider')
        logger.info(f"Testing email for provider: {provider}")
        
        # Get provider-specific settings
        username = Settings.get_value(f'{provider}_username')
        password = Settings.get_value(f'{provider}_password')
        
        logger.info(f"Attempting to send test email using username: {username}")
        
        if not username or not password:
            logger.warning(f"Incomplete settings for {provider}. Username present: {bool(username)}, Password present: {bool(password)}")
            return render_template('_test_result.html', 
                                success=False, 
                                message="Email settings are incomplete. Please save your settings first.")

        # Create a new Flask-Mail instance for testing
        from flask_mail import Mail
        test_mail = Mail()

        # Configure mail settings for test
        if provider == 'outlook':
            mail_config = {
                'MAIL_SERVER': 'smtp.office365.com',
                'MAIL_PORT': 587,
                'MAIL_USE_TLS': True,
                'MAIL_USE_SSL': False,
                'MAIL_USERNAME': username,
                'MAIL_PASSWORD': password,
                'MAIL_DEFAULT_SENDER': username,  # Use authenticated email as sender
                'MAIL_DEBUG': True,
                'MAIL_MAX_EMAILS': 1,
                'MAIL_SUPPRESS_SEND': False,
                'MAIL_USE_CREDENTIALS': True,
                'MAIL_FORCE_TLS': True
            }
            
            # Update the notification email setting to match the authenticated user
            Settings.set_value('notification_emails', username)
            Settings.set_value('sender_email', username)
            
        elif provider == 'gmail':
            mail_config = {
                'MAIL_SERVER': 'smtp.gmail.com',
                'MAIL_PORT': 587,
                'MAIL_USE_TLS': True,
                'MAIL_USE_SSL': False,
                'MAIL_USERNAME': username,
                'MAIL_PASSWORD': password,
                'MAIL_DEFAULT_SENDER': username,
                'MAIL_DEBUG': True,
                'MAIL_MAX_EMAILS': 1,
                'MAIL_SUPPRESS_SEND': False
            }
        elif provider == 'exchange':
            exchange_server = Settings.get_value('exchange_server')
            if not exchange_server:
                return render_template('_test_result.html', 
                                    success=False, 
                                    message="Exchange server URL is required")
            mail_config = {
                'MAIL_SERVER': exchange_server,
                'MAIL_PORT': 587,
                'MAIL_USE_TLS': True,
                'MAIL_USE_SSL': False,
                'MAIL_USERNAME': username,
                'MAIL_PASSWORD': password,
                'MAIL_DEFAULT_SENDER': username
            }

        # Update app config with mail settings
        app.config.update(mail_config)

        # Log mail configuration (excluding password)
        safe_config = {k: v for k, v in mail_config.items() if k != 'MAIL_PASSWORD'}
        logger.info(f"Testing with mail configuration: {safe_config}")

        # Initialize the test mail instance with the new configuration
        test_mail.init_app(app)

        # Create test message
        msg = Message(
            subject='Test Email from Aman Contracts System',
            sender=username,
            recipients=[username],  # Send to self for testing
            body="This is a test email to verify your email settings."
        )

        # Try to send using the test mail instance
        test_mail.send(msg)
        
        success_message = f"Test email sent successfully to {username}. Please check your inbox."
        logger.info(f"Test email sent successfully using {provider} to {username}")
        return render_template('_test_result.html', 
                             success=True, 
                             message=success_message)
                             
    except Exception as e:
        error_msg = str(e)
        
        # Provide user-friendly error messages
        if "SendAsDenied" in error_msg:
            error_msg = "Permission denied: Your account is not allowed to send as another address."
        elif "5.7.139" in error_msg:  # Outlook specific error
            error_msg = (
                "Authentication failed for Office 365. Please check:\n"
                "1. Your email and password are correct\n"
                "2. Multi-Factor Authentication (MFA) is properly set up\n"
                "3. App password is used if MFA is enabled\n"
                "4. Account has SMTP AUTH enabled in Office 365"
            )
        elif "invalid login" in error_msg.lower() or "Username and Password not accepted" in error_msg:
            error_msg = "Invalid login credentials. Please check your email and password."
        elif "ssl" in error_msg.lower():
            error_msg = "SSL/TLS connection failed. Please check your mail server settings."
        elif "authentication" in error_msg.lower():
            error_msg = "Authentication failed. If using Office 365, make sure SMTP AUTH is enabled."
        
        logger.error(f"Error testing email settings for {provider} with username {username}: {error_msg}", exc_info=True)
        return render_template('_test_result.html', 
                             success=False, 
                             message=f"Failed to send test email: {error_msg}")

@app.route('/notification-settings/recipients', methods=['POST'])
@login_required
@admin_required
def save_recipients_settings():
    try:
        notification_emails = request.form.get('notification_emails', '').strip()
        setting = Settings.query.filter_by(key='notification_emails').first()
        Settings.set_value('notification_emails', notification_emails)
        
        # Log with better context
        log_audit('update', 'notification_settings', setting.id if setting else None,
                 f'Updated notification recipients to: {notification_emails}')
        flash('Notification recipients updated successfully', 'success')
        
    except Exception as e:
        flash(f'Error saving recipients: {str(e)}', 'error')
        log_audit('error', 'notification_settings', None, f'Error updating recipients: {str(e)}')

    return '', 204

@app.route('/scheduler/status', methods=['GET'])
@login_required
@admin_required
def scheduler_status():
    """Get the status of scheduled jobs"""
    jobs = []
    for job in email_scheduler.get_jobs():  # Use email_scheduler instead of scheduler
        jobs.append({
            'id': job.id,
            'name': job.name or job.id,
            'next_run': job.next_run_time.strftime('%Y-%m-%d %H:%M:%S') if job.next_run_time else 'Not Scheduled',
            'trigger': str(job.trigger),
            'active': job.next_run_time is not None
        })
    
    # Also get contract scheduler jobs
    for job in scheduler.get_jobs():
        jobs.append({
            'id': job.id,
            'name': job.name or job.id,
            'next_run': job.next_run_time.strftime('%Y-%m-%d %H:%M:%S') if job.next_run_time else 'Not Scheduled',
            'trigger': str(job.trigger),
            'active': job.next_run_time is not None
        })
    
    return {
        'status': 'Running',
        'jobs': jobs
    }

@app.route('/test-scheduler', methods=['POST'])
@login_required
@admin_required
def test_scheduler():
    """Test scheduler job"""
    job_type = request.args.get('type', '')
    
    try:
        logger.info(f"Testing scheduler job: {job_type}")
        
        if 'notify_event_' in job_type:
            event_id = job_type.split('notify_event_')[1]
            event = CollaborationEvent.query.get(event_id)
            if event:
                success, recipients = notify_collaboration_update(event)
                message = f"Email notification sent to: {', '.join(recipients)}" if success else "Failed to send notification"
            else:
                success = False
                message = "Event not found"
        elif job_type == 'Contract Expiry Check':
            message, success = send_contract_notifications()
        elif job_type == 'Periodic Contract Report':
            message, success = send_periodic_report()
        else:
            return jsonify({
                'success': False,
                'message': f'Unknown job type: {job_type}'
            }), 400
            
        logger.info(f"Test result for {job_type}: {success}, {message}")
        return jsonify({
            'success': success,
            'message': message
        })
        
    except Exception as e:
        logger.error(f"Error testing scheduler job {job_type}: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'message': str(e)
        })

@app.route('/scheduler-test')
@login_required
@admin_required
def scheduler_test():
    """Page for testing scheduler jobs"""
    try:
        # Get current scheduler status from the imported scheduler instance
        scheduler_info = {
            'status': 'Running' if scheduler.running else 'Stopped',
            'jobs': []
        }
        
        # Get job information from both schedulers
        all_jobs = []
        
        # Add jobs from main scheduler
        for job in scheduler.get_jobs():
            all_jobs.append({
                'id': job.id,
                'name': job.name or job.id,
                'next_run': job.next_run_time.strftime('%Y-%m-%d %H:%M:%S') if job.next_run_time else 'Not Scheduled',
                'trigger': str(job.trigger),
                'active': job.next_run_time is not None
            })
            
        # Add jobs from email scheduler
        for job in email_scheduler.get_jobs():
            all_jobs.append({
                'id': job.id,
                'name': 'Email Notification' if job.id.startswith('notify_event_') else job.name or job.id,
                'next_run': job.next_run_time.strftime('%Y-%m-%d %H:%M:%S') if job.next_run_time else 'Not Scheduled',
                'trigger': str(job.trigger),
                'active': job.next_run_time is not None
            })
        
        scheduler_info['jobs'] = sorted(all_jobs, key=lambda x: x['next_run'] if x['next_run'] != 'Not Scheduled' else '9999')
        
        return render_template('scheduler_test.html', scheduler_info=scheduler_info)
        
    except Exception as e:
        logger.error(f"Error in scheduler test page: {str(e)}", exc_info=True)
        flash('Error loading scheduler information', 'error')
        return redirect(url_for('dashboard'))

# Move this function before init_app()
def check_mail_configuration():
    """Check if any mail provider is properly configured"""
    try:
        # Get enabled provider
        enabled_provider = Settings.get_value('mail_provider_enabled', '')
        logger.info(f"[check_mail_configuration] Checking mail configuration for enabled provider: {enabled_provider}")
        
        if not enabled_provider:
            logger.warning("[check_mail_configuration] No mail provider enabled")
            return False
            
        # Get provider settings
        username = Settings.get_value(f'{enabled_provider}_username', '')
        password = Settings.get_value(f'{enabled_provider}_password', '')
        
        # Check if both username and password are set
        is_configured = bool(username and password)
        
        logger.info(f"[check_mail_configuration] Mail configuration status: {is_configured}")
        logger.info(f"[check_mail_configuration] Username exists: {bool(username)}, Password exists: {bool(password)}")
        
        return is_configured
        
    except Exception as e:
        logger.error(f"[check_mail_configuration] Error checking mail configuration: {str(e)}")
        return False

def init_app():
    """Initialize the Flask application"""
    with app.app_context():
        try:
            # Create all tables
            db.create_all()
            
            # Initialize settings
            init_settings()
            
            # Create default admin user
            admin = User.query.filter_by(username='aman').first()
            if admin:
                # Update existing admin user
                admin.user_type = UserType.ADMIN.value
                admin.set_password('hamdan')  # Reset password
                db.session.commit()
                logger.info("Updated existing admin user")
                logger.info(f"Admin user password hash: {admin.password_hash}")
            else:
                # Create new admin user
                admin = User(
                    name='Aman Admin',
                    username='aman',
                    email='admin@aman.ps',
                    user_type=UserType.ADMIN.value
                )
                admin.set_password('hamdan')
                db.session.add(admin)
                db.session.commit()
                logger.info("Created default admin user")
                logger.info(f"Admin user password hash: {admin.password_hash}")
            
            # Check mail configuration
            is_configured = check_mail_configuration()
            logger.info(f"[init_app] Initial mail configuration check: {is_configured}")
            
            # Setup mail after database is initialized
            setup_mail(app)
            
            # Initialize scheduler
            init_scheduler(app)
        
        except Exception as e:
            logger.error(f"Error in init_app: {str(e)}")
            raise

@app.before_request
def before_request():
    """Check mail configuration before each request"""
    if request.endpoint != 'static':  # Skip for static files
        is_configured = check_mail_configuration()
        logger.info(f"[before_request] Mail configuration check for {request.endpoint}: {is_configured}")

def try_bind_port(port):
    """Try to bind to a port and return True if successful"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('0.0.0.0', port))
            return True
    except OSError:
        return False

@app.route('/settings/provider', methods=['GET'])
@login_required
@admin_required
def get_provider_settings():
    """Get settings for specific mail provider"""
    provider = request.args.get('mail_provider', 'outlook')
    settings = {
        'smtp_username': Settings.get_value('smtp_username', ''),
        'smtp_password': '',  # Don't send the actual password
        'exchange_server': Settings.get_value('exchange_server', '') if provider == 'exchange' else None,
        'notification_emails': Settings.get_value('notification_emails', ''),
        'mail_provider': provider
    }
    
    return render_template('_provider_settings.html', 
                         provider=provider,
                         settings=settings)

@app.route('/settings/get_provider_config')
@login_required
@admin_required
def get_provider_config():
    """Get configuration for specific mail provider"""
    try:
        provider = request.args.get('provider', 'outlook')
        
        # Base configuration
        config = {
            'mail_provider': Settings.get_value('mail_provider', 'outlook'),
            'mail_provider_enabled': Settings.get_value('mail_provider_enabled', 'outlook'),
        }
        
        # Provider-specific settings
        if provider == 'outlook':
            config.update({
                'outlook_username': Settings.get_value('outlook_username', ''),
                'outlook_server': 'smtp.office365.com',  # Default server
                'outlook_port': '587',  # Default port
            })
        elif provider == 'gmail':
            config.update({
                'gmail_username': Settings.get_value('gmail_username', ''),
                'gmail_server': 'smtp.gmail.com',  # Default server
                'gmail_port': '587',  # Default port
            })
        elif provider == 'exchange':
            config.update({
                'exchange_username': Settings.get_value('exchange_username', ''),
                'exchange_server': Settings.get_value('exchange_server', ''),
                'exchange_port': Settings.get_value('exchange_port', '587'),
            })
            
        # Add notification settings
            config.update({
                'notification_emails': Settings.get_value('notification_emails', ''),
                'expiry_notifications_enabled': Settings.get_value('expiry_notifications_enabled', 'true'),
                'periodic_notifications_enabled': Settings.get_value('periodic_notifications_enabled', 'false'),
            })
        
        logger.info(f"Retrieved config for provider {provider}: {config}")
        return jsonify(config)
        
    except Exception as e:
        logger.error(f"Error getting provider config: {str(e)}")
        return jsonify({
            'error': str(e),
            'message': 'Error retrieving provider configuration'
        }), 500

@app.route('/settings/toggle-provider', methods=['POST'])
@login_required
@admin_required
def toggle_provider():
    """Enable a mail provider and disable others"""
    try:
        data = request.get_json()
        provider = data.get('provider')
        
        if provider not in ['outlook', 'gmail', 'exchange']:
            return jsonify({
                'success': False,
                'message': 'Invalid provider'
            }), 400
        
        # Update the enabled provider
        Settings.set_value('mail_provider_enabled', provider)
        Settings.set_value('mail_provider', provider)
        
        # Reconfigure mail settings
        setup_mail(app)
        
        provider_names = {
            'outlook': 'Microsoft 365',
            'gmail': 'Gmail',
            'exchange': 'Exchange Server'
        }
        
        return jsonify({
            'success': True,
            'provider': provider_names.get(provider, provider),
            'message': f'{provider_names.get(provider, provider)} is now the active email provider'
        })
        
    except Exception as e:
        logger.error(f"Error toggling provider: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error updating provider settings'
        }), 500

@app.route('/settings/verify', methods=['GET'])
@login_required
@admin_required
def verify_settings():
    """Verify saved email settings"""
    provider = request.args.get('provider', 'gmail')
    settings_check = {
        'username_saved': bool(Settings.get_value(f'{provider}_username')),
        'password_saved': bool(Settings.get_value(f'{provider}_password')),
        'provider_enabled': Settings.get_value('mail_provider_enabled') == provider,
        'current_provider': Settings.get_value('mail_provider')
    }
    return jsonify(settings_check)

# Add this after other model definitions
class Extension(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    agreement_id = db.Column(db.Integer, db.ForeignKey('contract.id'), nullable=False)
    effective_date = db.Column(db.Date, nullable=False)
    validity_period = db.Column(db.Integer, nullable=False)  # in days
    expiry_date = db.Column(db.Date, nullable=False)
    file_path = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    contract = db.relationship('Contract', backref=db.backref('extensions', lazy=True))

# Add this method to the Agreement class
def get_latest_expiry_date(self):
    dates = [self.expiry_date]
    for extension in self.extensions:
        dates.append(extension.expiry_date)
    return max(dates)

# Add these helper functions
def check_extension_overlap(contract, new_extension_start, new_extension_end):
    """
    Check if a new extension overlaps with existing extensions
    Returns: (bool, list) - (has_overlap, overlapping_extensions)
    """
    overlapping = []
    
    for ext in contract.extensions:
        # Calculate overlap
        overlap_start = max(ext.effective_date, new_extension_start)
        overlap_end = min(ext.expiry_date, new_extension_end)
        
        # If there's an overlap of more than 30 days
        if overlap_start <= overlap_end:
            overlap_days = (overlap_end - overlap_start).days
            if overlap_days > 30:  # More than a month overlap
                overlapping.append({
                    'id': ext.id,
                    'effective_date': ext.effective_date.strftime('%Y-%m-%d'),
                    'expiry_date': ext.expiry_date.strftime('%Y-%m-%d'),
                    'overlap_days': overlap_days
                })
    
    return bool(overlapping), overlapping

# Add these routes after other routes
@app.route('/contract/<int:contract_id>/add_extension', methods=['GET', 'POST'])
@login_required
def add_extension(contract_id):
    contract = Contract.query.get_or_404(contract_id)
    
    if request.method == 'POST':
        effective_date = datetime.strptime(request.form['effective_date'], '%Y-%m-%d').date()
        validity_period = int(request.form['validity_period'])
        expiry_date = datetime.strptime(request.form['expiry_date'], '%Y-%m-%d').date()
        force_save = request.form.get('force_save') == 'true'
        
        # Check for overlapping extensions if not forcing save
        if not force_save:
            has_overlap, overlapping = check_extension_overlap(contract, effective_date, expiry_date)
            if has_overlap:
                # Return JSON response with overlap information
                return jsonify({
                    'status': 'overlap',
                    'message': 'Extension overlaps with existing extensions',
                    'overlapping': overlapping
                }), 409
        
        # Proceed with saving the extension
        extension = Extension(
            agreement_id=contract_id,
            effective_date=effective_date,
            validity_period=validity_period,
            expiry_date=expiry_date
        )
        
        if 'extension_file' in request.files:
            file = request.files['extension_file']
            if file and allowed_file(file.filename):
                # Get original file extension
                file_ext = file.filename.rsplit('.', 1)[1].lower()
                filename = secure_filename(f"extension_{contract_id}_{int(time.time())}.{file_ext}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                extension.file_path = filename
        
        db.session.add(extension)
        
        # Update contract expiry date
        contract.expiry_date = contract.get_latest_expiry_date()
        
        db.session.commit()
        flash('Extension added successfully', 'success')
        
        # If it was an AJAX request, return JSON response
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'success', 'redirect': url_for('view_contract', contract_id=contract_id)})
        
        return redirect(url_for('view_contract', contract_id=contract_id))
    
    return render_template('add_extension.html', contract=contract)

@app.route('/extension/<int:extension_id>/view_file')
@login_required
def view_extension_file(extension_id):
    extension = Extension.query.get_or_404(extension_id)
    if not extension.file_path:
        flash('No file available', 'error')
        return redirect(url_for('view_contract', contract_id=extension.agreement_id))
    
    # Get the file's mime type based on extension
    file_ext = extension.file_path.rsplit('.', 1)[1].lower()
    mime_types = {
        'pdf': 'application/pdf',
        'doc': 'application/msword',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xls': 'application/vnd.ms-excel',
        'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    }
    
    # Always force download for non-PDF files
    as_attachment = file_ext != 'pdf'
    
    # For Word files, ensure they're downloaded with the correct extension
    if file_ext in ['doc', 'docx', 'xls', 'xlsx']:
        response = send_from_directory(
            app.config['UPLOAD_FOLDER'],
            extension.file_path,
            mimetype=mime_types.get(file_ext, 'application/octet-stream'),
            as_attachment=True
        )
        # Set the correct filename for download
        response.headers['Content-Disposition'] = f'attachment; filename="{extension.file_path}"'
        return response
    
    # For PDFs, display in browser
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        extension.file_path,
        mimetype=mime_types.get(file_ext, 'application/octet-stream'),
        as_attachment=False
    )

# Add this near the top of the file with other utility functions
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'xls', 'xlsx'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/extension/<int:extension_id>', methods=['DELETE'])
@login_required
def delete_extension(extension_id):
    try:
        extension = Extension.query.get_or_404(extension_id)
        
        # Delete the PDF file if it exists
        if extension.file_path:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], extension.file_path)
            if os.path.exists(file_path):
                os.remove(file_path)
        
        # Get the contract to update its expiry date
        contract = Contract.query.get(extension.agreement_id)
        
        # Delete the extension
        db.session.delete(extension)
        
        # Update the contract's expiry date if there are other extensions
        if contract.extensions:
            contract.expiry_date = contract.get_latest_expiry_date()
        
        db.session.commit()
        
        flash('Extension deleted successfully', 'success')
        return '', 204
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting extension: {str(e)}", exc_info=True)
        return str(e), 500

@app.route('/extension/<int:extension_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_extension(extension_id):
    extension = Extension.query.get_or_404(extension_id)
    contract = Contract.query.get(extension.agreement_id)
    
    if request.method == 'POST':
        effective_date = datetime.strptime(request.form['effective_date'], '%Y-%m-%d').date()
        validity_period = int(request.form['validity_period'])
        expiry_date = datetime.strptime(request.form['expiry_date'], '%Y-%m-%d').date()
        force_save = request.form.get('force_save') == 'true'
        
        # Check for overlapping extensions if not forcing save
        if not force_save:
            has_overlap, overlapping = check_extension_overlap(contract, effective_date, expiry_date)
            if has_overlap:
                # Return JSON response with overlap information
                return jsonify({
                    'status': 'overlap',
                    'message': 'Extension overlaps with existing extensions',
                    'overlapping': overlapping
                }), 409
        
        # Update extension details
        extension.effective_date = effective_date
        extension.validity_period = validity_period
        extension.expiry_date = expiry_date
        
        # Handle file upload if new file is provided
        if 'extension_file' in request.files:
            file = request.files['extension_file']
            if file and file.filename and allowed_file(file.filename):
                # Delete old file if it exists
                if extension.file_path:
                    old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], extension.file_path)
                    if os.path.exists(old_file_path):
                        os.remove(old_file_path)
                
                # Get original file extension
                file_ext = file.filename.rsplit('.', 1)[1].lower()
                filename = secure_filename(f"extension_{extension.agreement_id}_{int(time.time())}.{file_ext}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                extension.file_path = filename
        
        # Update contract expiry date
        contract.expiry_date = contract.get_latest_expiry_date()
        
        db.session.commit()
        flash('Extension updated successfully', 'success')
        
        # If it was an AJAX request, return JSON response
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'success', 'redirect': url_for('view_contract', contract_id=contract.id)})
        
        return redirect(url_for('view_contract', contract_id=contract.id))
    
    return render_template('edit_extension.html', extension=extension, contract=contract)

@app.route('/preview/<int:attachment_id>')
@login_required
def preview_attachment(attachment_id):
    attachment = Attachment.query.get_or_404(attachment_id)
    
    # Get the file's mime type based on extension
    file_ext = attachment.file_path.rsplit('.', 1)[1].lower()
    mime_types = {
        'pdf': 'application/pdf',
        'doc': 'application/msword',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xls': 'application/vnd.ms-excel',
        'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    }
    
    # Always force download for non-PDF files
    as_attachment = file_ext != 'pdf'
    
    # For Word files, ensure they're downloaded with the correct extension
    if file_ext in ['doc', 'docx', 'xls', 'xlsx']:
        response = send_from_directory(
            app.config['UPLOAD_FOLDER'],
            attachment.file_path,
            mimetype=mime_types.get(file_ext, 'application/octet-stream'),
            as_attachment=True
        )
        # Set the correct filename for download
        response.headers['Content-Disposition'] = f'attachment; filename="{attachment.filename}"'
        return response
    
    # For PDFs, display in browser
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        attachment.file_path,
        mimetype=mime_types.get(file_ext, 'application/octet-stream'),
        as_attachment=False
    )

# Add these utility functions
def generate_access_token():
    """Generate a unique access token"""
    return secrets.token_urlsafe(32)

def generate_email_signature():
    """Generate a unique email signature"""
    return secrets.token_hex(16)

@app.route('/legal-offices')
@login_required
@admin_required
def legal_offices():
    """List legal offices"""
    try:
        # Prevent Legal Representatives from accessing this page
        if current_user.user_type == UserType.LEGAL_REP.value:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard'))
            
        # Get all legal offices with pagination
        page = request.args.get('page', 1, type=int)
        offices = LegalOffice.query.order_by(LegalOffice.name).paginate(
            page=page, per_page=10, error_out=False
        )
        
        return render_template('legal_offices.html', offices=offices)
        
    except Exception as e:
        logger.error(f"Error in legal_offices: {str(e)}")
        return handle_error(e)

@app.route('/legal-office/new', methods=['GET', 'POST'])
@login_required
@admin_required
def new_legal_office():
    """Create new legal office"""
    try:
        if request.method == 'POST':
            office = LegalOffice(
                name=request.form['name'],
                address=request.form['address'],
                phone=request.form['phone'],
                email=request.form['email']
            )
            
            db.session.add(office)
            db.session.commit()
            
            log_audit('create', 'legal_office', office.id, f"Created legal office: {office.name}")
            flash('Legal office added successfully', 'success')
            return redirect(url_for('legal_offices'))
            
        # Pass None as office for new office form
        return render_template('legal_office_form.html', 
                             title='New Legal Office',
                             office=None)
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating legal office: {str(e)}")
        flash('Error creating legal office', 'error')
        return redirect(url_for('legal_offices'))

@app.route('/legal-office/<int:office_id>/representatives')
@login_required
@admin_required
def office_representatives(office_id):
    office = LegalOffice.query.get_or_404(office_id)
    return render_template('representatives.html', office=office)

@app.route('/legal-office/<int:office_id>/representative/new', methods=['GET', 'POST'])
@login_required
@admin_required
def new_representative(office_id):
    """Create new legal representative"""
    try:
        office = LegalOffice.query.get_or_404(office_id)
        
        if request.method == 'POST':
            # Create representative
            representative = LegalRepresentative(
                office_id=office_id,
                name=request.form['name'],
                email=request.form['email'],
                phone=request.form['phone'],
                position=request.form['position']
            )
            db.session.add(representative)
            
            # Create user account if requested
            if request.form.get('create_user') == 'on':
                username = request.form['username']
                
                # Check if username exists
                if User.query.filter_by(username=username).first():
                    raise ValueError("Username already exists")
                
                # Create user with password token and set user type to Legal Representative
                user = User(
                    name=representative.name,
                    username=username,
                    email=representative.email,
                    user_type=UserType.LEGAL_REP.value
                )
                
                # Generate password setup token
                token = secrets.token_urlsafe(32)
                user.password_token = token
                user.token_expiry = datetime.utcnow() + timedelta(hours=24)
                
                # Set temporary password
                temp_password = secrets.token_hex(16)
                user.set_password(temp_password)
                
                db.session.add(user)
                
                # Send password setup email
                setup_url = url_for('set_password', token=token, _external=True)
                html = render_template('emails/set_password.html',
                                    name=user.name,
                                    username=user.username,
                                    setup_url=setup_url)
                
                # Get sender email from settings
                enabled_provider = Settings.get_value('mail_provider_enabled', 'outlook')
                sender_email = Settings.get_value(f'{enabled_provider}_username', '')
                
                msg = Message(
                    subject='Set Your Password - Aman Contracts Management System',
                    sender=sender_email,
                    recipients=[user.email],
                    html=html
                )
                mail.send(msg)
            else:
                # Set password directly
                user.set_password(request.form['password'])
            
            db.session.add(user)
            db.session.commit()
            
            log_audit('create', 'legal_representative', representative.id, 
                     f'Added representative {representative.name} to office {office.name}')
            flash('Representative added successfully', 'success')
            return redirect(url_for('office_representatives', office_id=office_id))
            
        return render_template('representative_form.html', office=office, representative=None)
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding representative: {str(e)}")
        flash(str(e), 'error')
        return redirect(url_for('office_representatives', office_id=office_id))

# Add these routes for collaboration management
@app.route('/collaborations')
@login_required
def collaborations():
    """View all collaborations"""
    # Get filter parameters
    status = request.args.get('status')
    office_id = request.args.get('office_id')
    collab_type = request.args.get('type')
    
    # Base query
    query = Collaboration.query
    
    # Apply filters
    if status:
        query = query.filter_by(status=status)
    if office_id:
        query = query.filter_by(office_id=int(office_id))
    if collab_type == 'contract':
        query = query.filter(Collaboration.contract_id.isnot(None))
    elif collab_type == 'lead':
        query = query.filter(Collaboration.contract_id.is_(None))
    
    # Get paginated results
    page = request.args.get('page', 1, type=int)
    collaborations = query.order_by(Collaboration.updated_at.desc()).paginate(
        page=page, per_page=10, error_out=False)
    
    # Get legal offices for filter
    legal_offices = LegalOffice.query.filter_by(is_active=True).all()
    
    # Get active contracts for the new collaboration modal
    contracts = Contract.query.filter_by(is_active=True).all()  # Add this line
    
    return render_template('collaborations.html',
                         collaborations=collaborations,
                         legal_offices=legal_offices,
                         contracts=contracts)  # Add contracts to template context

@app.route('/collaboration/new', methods=['GET', 'POST'])
@login_required
def new_collaboration():
    """Create new collaboration"""
    try:
        if request.method == 'POST':
            # Get form data
            title = request.form.get('title')
            description = request.form.get('description')
            office_id = request.form.get('office_id')
            contract_id = request.form.get('contract_id')  # This might be None for new leads
            
            # Try both possible field names for representatives
            representatives = request.form.getlist('representatives[]') or request.form.getlist('representative_ids[]')
            
            logger.info(f"Creating new collaboration - Title: {title}, Contract ID: {contract_id}")
            logger.info(f"Form data - Office ID: {office_id}")
            logger.info(f"Form data - Representatives: {representatives}")
            logger.info(f"All form data: {request.form}")
            
            if not representatives:
                logger.error("No representatives selected")
                flash('Please select at least one representative', 'error')
                return redirect(url_for('collaborations'))
            
            # Create collaboration
            collaboration = Collaboration(
                title=title,
                description=description,
                office_id=office_id,
                contract_id=contract_id,  # Will be None for leads
                created_by_id=current_user.id,
                status='open'
            )
            db.session.add(collaboration)
            db.session.flush()  # Get ID before committing
            
            # Handle file attachment if present
            stored_filename = None
            original_filename = None
            if 'attachment' in request.files:
                file = request.files['attachment']
                if file and file.filename:
                    result = save_collaboration_file(file, collaboration.id)
                    if result and result[0]:
                        stored_filename, original_filename = result
                        logger.info(f"Saved attachment: {original_filename} as {stored_filename}")
            
            # Create initial comment with description
            initial_comment = CollaborationEvent(
                collaboration_id=collaboration.id,
                event_type='comment',
                content=description,  # Use the description as content
                created_by_id=current_user.id,
                stored_filename=stored_filename,  # Add the attachment if exists
                original_filename=original_filename
            )
            db.session.add(initial_comment)
            
            # Add representatives
            for rep_id in representatives:
                # Generate access token and signature
                access_token = secrets.token_urlsafe(32)
                signature = secrets.token_hex(16)
                
                assignment = CollaborationAssignment(
                    collaboration_id=collaboration.id,
                    representative_id=rep_id,
                    access_token=access_token,
                    email_signature=signature
                )
                db.session.add(assignment)
                db.session.flush()  # Get assignment ID
                
                # Send email notification
                representative = LegalRepresentative.query.get(rep_id)
                if representative and representative.email:
                    send_collaboration_email(collaboration, assignment)
                    logger.info(f"Sent collaboration email to {representative.email}")
            
            db.session.commit()
            flash('Collaboration created successfully', 'success')
            return redirect(url_for('view_collaboration', collab_id=collaboration.id))
            
        # For GET requests
        contract_id = request.args.get('contract_id')  # Get contract_id from query params
        contract = Contract.query.get(contract_id) if contract_id else None
        offices = LegalOffice.query.filter_by(is_active=True).order_by(LegalOffice.name).all()
        
        logger.info(f"Rendering new collaboration form - Contract ID: {contract_id}, Found offices: {len(offices)}")
        
        return render_template('collaboration_form.html', 
                             offices=offices,
                             contract=contract,
                             title='New Collaboration')
                             
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating collaboration: {str(e)}")
        flash('Error creating collaboration', 'error')
        return redirect(url_for('collaborations'))

@app.route('/collaboration/save', methods=['POST'])
@login_required
def save_collaboration():
    try:
        contract_id = request.form.get('contract_id', type=int)
        office_id = request.form.get('office_id', type=int)
        representatives = request.form.getlist('representatives')
        
        # Create collaboration
        collaboration = Collaboration(
            title=request.form['title'],
            description=request.form['description'],
            contract_id=contract_id,
            office_id=office_id,
            created_by_id=current_user.id
        )
        db.session.add(collaboration)
        db.session.flush()  # Get collaboration ID
        
        # Create assignments for selected representatives
        for rep_id in representatives:
            assignment = CollaborationAssignment(
                collaboration_id=collaboration.id,
                representative_id=int(rep_id),
                access_token=generate_access_token(),
                email_signature=generate_email_signature()
            )
            db.session.add(assignment)
        
        # Handle file uploads
        if 'attachments' in request.files:
            files = request.files.getlist('attachments')
            for file in files:
                if file and file.filename and allowed_file(file.filename):
                    # Save file
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    
                    # Create file upload event
                    event = CollaborationEvent(
                        collaboration_id=collaboration.id,
                        event_type='file_upload',
                        created_by_id=current_user.id,
                        file_path=filename,
                        file_name=file.filename
                    )
                    db.session.add(event)
        
        db.session.commit()
        
        # Send emails to representatives
        for assignment in collaboration.assignments:
            send_collaboration_email(collaboration, assignment)
        
        log_audit('create', 'collaboration', collaboration.id, 
                 f'Created collaboration: {collaboration.title}')
        flash('Collaboration created successfully', 'success')
        
        return redirect(url_for('view_collaboration', collab_id=collaboration.id))
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating collaboration: {str(e)}", exc_info=True)
        flash('Error creating collaboration', 'error')
        return redirect(url_for('new_collaboration'))

@app.route('/collaboration/<int:collab_id>')
@login_required
def view_collaboration(collab_id):
    collaboration = Collaboration.query.get_or_404(collab_id)
    
    # Get pending notification jobs from scheduler
    pending_notifications = set()
    for job in email_scheduler.get_jobs():
        if job.id.startswith('notify_event_'):
            event_id = int(job.id.split('_')[-1])
            pending_notifications.add(event_id)
    
    return render_template('view_collaboration.html', 
                         collaboration=collaboration,
                         now=datetime.utcnow(),
                         pending_notifications=pending_notifications)

def schedule_event_notification(event, delay_seconds=120):
    """Schedule notification for collaboration event"""
    try:
        # Schedule notification job
        job = scheduler.add_job(
            func=notify_collaboration_update,
            trigger='date',
            run_date=datetime.now() + timedelta(seconds=delay_seconds),
            args=[event],
            id=f'notify_event_{event.id}',
            name=f'Send notification for event {event.id}'
        )
        
        logger.info(f"Scheduled notification for event {event.id} at {job.next_run_time}")
        return True
        
    except Exception as e:
        logger.error(f"Error scheduling notification: {str(e)}")
        return False


# Add a decorator for checking login status
def login_required_with_response(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'success': False, 'require_login': True}), 401
        return f(*args, **kwargs)
    return decorated_function

# Add this near the top with other app configurations
app.config['BASE_URL'] = 'http://localhost:5001'  # Update this for production

@app.route('/collaboration/file/<int:event_id>')
@login_required
def download_collaboration_file(event_id):
    """Download collaboration event file"""
    try:
        event = CollaborationEvent.query.get_or_404(event_id)
        logger.info(f"Downloading file for event {event_id}")
        
        if not event.stored_filename or not event.original_filename:
            logger.error(f"No file associated with event {event_id}")
            flash('No file associated with this event', 'error')
            return redirect(url_for('view_collaboration', collab_id=event.collaboration_id))
        
        # Files should be in uploads/chatFiles directory
        chat_files_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'chatFiles')
        file_path = os.path.join(chat_files_dir, event.stored_filename)
        
        logger.info(f"Looking for file at: {file_path}")
        logger.info(f"Stored filename: {event.stored_filename}")
        logger.info(f"Original filename: {event.original_filename}")
        
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            flash('The requested file could not be found', 'error')
            return redirect(url_for('view_collaboration', collab_id=event.collaboration_id))
            
        return send_from_directory(
            chat_files_dir,
            event.stored_filename,
            as_attachment=True,
            download_name=event.original_filename
        )
        
    except Exception as e:
        logger.error(f"Error downloading file: {str(e)}")
        flash('Error downloading file', 'error')
        return redirect(url_for('dashboard'))

def save_collaboration_file(file, event_id):
    """Save collaboration file with unique name"""
    try:
        if not file or not file.filename:
            logger.warning("No file or empty filename provided")
            return None, None
            
        logger.info(f"Processing file: {file.filename} for event {event_id}")
        
        # Generate unique filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        random_str = secrets.token_hex(4)  # Add random string for extra uniqueness
        file_ext = os.path.splitext(file.filename)[1]
        stored_filename = f"collab_event_{event_id}_{timestamp}_{random_str}{file_ext}"
        
        # Ensure chatFiles directory exists
        chat_files_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'chatFiles')
        os.makedirs(chat_files_dir, exist_ok=True)
        
        # Save file
        file_path = os.path.join(chat_files_dir, stored_filename)
        file.save(file_path)
        
        logger.info(f"Saved file {file.filename} as {stored_filename} in {chat_files_dir}")
        return stored_filename, file.filename
        
    except Exception as e:
        logger.error(f"Error saving file: {str(e)}", exc_info=True)
        return None, None

# Make sure this is at the module level, not inside any other function
@app.route('/collaboration/event/<int:event_id>/reply', methods=['POST'])
@login_required
def add_reply(event_id):
    """Add reply to a collaboration event"""
    try:
        # Get parent event
        parent_event = CollaborationEvent.query.get_or_404(event_id)
        content = request.form.get('content')
        
        logger.info(f"Adding reply to event {event_id}")
        logger.info(f"Content: {content}")
        
        if not content:
            raise ValueError("Reply content cannot be empty")
        
        # Create reply event
        reply = CollaborationEvent(
            collaboration_id=parent_event.collaboration_id,
            event_type='comment',
            content=content,
            created_by_id=current_user.id if current_user.is_authenticated else None,
            representative_id=request.form.get('representative_id'),
            parent_id=event_id
        )
        
        db.session.add(reply)
        db.session.flush()  # Get the ID before commit
        
        # Handle file attachment if present
        if 'attachment' in request.files:
            file = request.files['attachment']
            if file and file.filename and allowed_file(file.filename):
                # Create chatFiles directory if it doesn't exist
                chat_files_dir = os.path.join(current_app.root_path, app.config['UPLOAD_FOLDER'], 'chatFiles')
                os.makedirs(chat_files_dir, exist_ok=True)
                
                # Generate unique filename
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                random_str = secrets.token_hex(4)
                file_ext = os.path.splitext(file.filename)[1]
                stored_filename = f"collab_{parent_event.collaboration_id}_reply_{reply.id}_{timestamp}_{random_str}{file_ext}"
                
                # Save file
                file_path = os.path.join(chat_files_dir, stored_filename)
                file.save(file_path)
                
                # Update reply with file info
                reply.stored_filename = stored_filename
                reply.original_filename = file.filename
        
        db.session.commit()
        logger.info(f"Successfully created reply {reply.id} to event {event_id}")
        
        # Return JSON response
        return jsonify({
            'success': True,
            'reply': {
                'id': reply.id,
                'content': reply.content,
                'author_name': current_user.name if current_user.is_authenticated else reply.representative.name,
                'created_at': reply.created_at.strftime('%Y-%m-%d %H:%M'),
                'attachment': {
                    'url': url_for('download_collaboration_file', event_id=reply.id) if reply.stored_filename else None,
                    'name': reply.original_filename if reply.stored_filename else None
                } if reply.stored_filename else None
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding reply: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    
@app.route('/collaboration/<int:collab_id>/comment', methods=['POST'])
@login_required
def add_comment(collab_id):
    """Add comment to collaboration"""
    try:
        collaboration = Collaboration.query.get_or_404(collab_id)
        content = request.form.get('content')
        
        logger.info(f"Adding comment to collaboration {collab_id}")
        
        # Create event
        event = CollaborationEvent(
            collaboration_id=collab_id,
            event_type='comment',
            content=content,
            created_by_id=current_user.id
        )
        db.session.add(event)
        db.session.flush()  # Get event ID
        
        # Handle file attachment
        attachment_data = None
        if 'attachment' in request.files:
            file = request.files['attachment']
            logger.info(f"Processing attachment: {file.filename}")
            
            if file and file.filename and allowed_file(file.filename):
                # Create chatFiles directory if it doesn't exist
                chat_files_dir = os.path.join(current_app.root_path, app.config['UPLOAD_FOLDER'], 'chatFiles')
                os.makedirs(chat_files_dir, exist_ok=True)
                logger.info(f"Using directory: {chat_files_dir}")
                
                # Generate unique filename
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                random_str = secrets.token_hex(4)
                file_ext = os.path.splitext(file.filename)[1]
                stored_filename = f"collab_{collab_id}_event_{event.id}_{timestamp}_{random_str}{file_ext}"
                
                # Save file
                file_path = os.path.join(chat_files_dir, stored_filename)
                file.save(file_path)
                logger.info(f"Saved file to: {file_path}")
                
                # Update event with file info
                event.stored_filename = stored_filename
                event.original_filename = file.filename
                logger.info(f"Updated event with file info: {stored_filename}")
                
                attachment_data = {
                    'url': url_for('download_collaboration_file', event_id=event.id),
                    'name': file.filename
                }
        
        db.session.commit()
        
        # Use notify_collaboration_update instead of schedule_event_notification
        from services.collaboration_notifications import notify_collaboration_update
        notify_collaboration_update(event)
        
        logger.info(f"Successfully added comment to collaboration {collab_id}")
        
        return jsonify({
            'success': True,
            'message': 'Comment added successfully',
            'event': {
                'id': event.id,
                'content': event.content,
                'author_name': current_user.name,
                'created_at': event.created_at.strftime('%Y-%m-%d %H:%M'),
                'attachment': attachment_data
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding comment: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/collaboration/<int:collab_id>/complete', methods=['POST'])
@login_required
def complete_collaboration(collab_id):
    try:
        collaboration = Collaboration.query.get_or_404(collab_id)
        collaboration.status = 'completed'
        
        # Add status change event
        event = CollaborationEvent(
            collaboration_id=collab_id,
            event_type='status_change',
            content='Collaboration marked as completed',
            created_by_id=current_user.id
        )
        db.session.add(event)
        
        db.session.commit()
        log_audit('update', 'collaboration', collab_id, 'Marked as completed')
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error completing collaboration: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

def schedule_event_notification(event, delay_seconds=120):
    """Schedule notification for collaboration event"""
    try:
        # Schedule notification job
        job = scheduler.add_job(
            func=notify_collaboration_update,
            trigger='date',
            run_date=datetime.now() + timedelta(seconds=delay_seconds),
            args=[event],
            id=f'notify_event_{event.id}',
            name=f'Send notification for event {event.id}'
        )
        
        logger.info(f"Scheduled notification for event {event.id} at {job.next_run_time}")
        return True
        
    except Exception as e:
        logger.error(f"Error scheduling notification: {str(e)}")
        return False

@app.route('/legal/comment/<token>', methods=['POST'])
def legal_comment(token):
    try:
        signature = request.args.get('sig')
        if not signature:
            return jsonify({'success': False, 'error': 'Invalid access'}), 400
        
        assignment = verify_access_token(token, signature)
        if not assignment:
            return jsonify({'success': False, 'error': 'Invalid access'}), 404
        
        # Create comment event
        event = CollaborationEvent(
            collaboration_id=assignment.collaboration_id,
            event_type='comment',
            content=request.form['content'],
            representative_id=assignment.representative_id
        )
        db.session.add(event)
        
        # Handle file attachments
        if 'attachments' in request.files:
            files = request.files.getlist('attachments')
            for file in files:
                if file and file.filename and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    
                    # Create file upload event
                    file_event = CollaborationEvent(
                        collaboration_id=assignment.collaboration_id,
                        event_type='file_upload',
                        representative_id=assignment.representative_id,
                        file_path=filename,
                        file_name=file.filename
                    )
                    db.session.add(file_event)
        
        assignment.collaboration.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding legal comment: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)})

# Add a decorator for checking login status
def login_required_with_response(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'success': False, 'require_login': True}), 401
        return f(*args, **kwargs)
    return decorated_function

# Update the route for completing collaboration
@app.route('/legal/complete/<token>', methods=['POST'])
@login_required_with_response
def legal_complete(token):
    try:
        signature = request.args.get('sig')
        if not signature:
            return jsonify({'success': False, 'error': 'Invalid access'}), 400
        
        assignment = verify_access_token(token, signature)
        if not assignment:
            return jsonify({'success': False, 'error': 'Invalid access'}), 404
        
        # Mark assignment as completed
        assignment.is_completed = True
        assignment.completed_at = datetime.utcnow()
        
        # Add completion event
        event = CollaborationEvent(
            collaboration_id=assignment.collaboration_id,
            event_type='status_change',
            content=f'Marked as completed by {assignment.representative.name}',
            representative_id=assignment.representative_id
        )
        db.session.add(event)
        
        # Check if all assignments are completed
        all_completed = all(a.is_completed for a in assignment.collaboration.assignments)
        if all_completed:
            assignment.collaboration.status = 'completed'
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Collaboration marked as completed'})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error completing collaboration: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/ajax-login', methods=['POST'])
def ajax_login():
    """Handle AJAX login requests"""
    username = request.form.get('username')
    password = request.form.get('password')
    collaboration_id = request.form.get('collaboration_id')
    
    logger.info(f"Login attempt for {username}")
    
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        login_user(user)
        logger.info(f"User {username} logged in successfully")
        
        # If we have a collaboration_id, redirect to view_collaboration
        if collaboration_id and collaboration_id != 'None':
            logger.info(f"Redirecting to collaboration {collaboration_id}")
            return jsonify({
                'success': True,
                'redirect_url': url_for('view_collaboration', collab_id=collaboration_id)
            })
        
        # Default redirect to dashboard
        logger.info("No collaboration_id found, redirecting to dashboard")
        return jsonify({
            'success': True,
            'redirect_url': url_for('dashboard')
        })
    else:
        logger.warning(f"Invalid login attempt for user: {username}")
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

@app.route('/legal/error/<error_type>')
def legal_error(error_type):
    """Handle legal access errors"""
    title = 'Access Error'
    collaboration_id = request.args.get('collaboration_id')
    
    logger.info(f"Legal error page - Type: {error_type}, Collaboration ID: {collaboration_id}")
    logger.info(f"Current user authenticated: {current_user.is_authenticated}")
    logger.info(f"Current session: {dict(session)}")
    
    if error_type == 'expired':
        if current_user.is_authenticated:
            # If user is already logged in, redirect to view_collaboration
            logger.info(f"Authenticated user on expired token page. Redirecting to collaboration {collaboration_id}")
            return redirect(url_for('view_collaboration', collab_id=collaboration_id))
        message = 'Please log in to view this collaboration.'
    else:
        message = 'Unable to access the requested collaboration.'
    
    logger.info(f"Rendering legal error page with message: {message}")
    return render_template('legal_error.html', 
                         error_type=error_type,
                         title=title,
                         message=message,
                         collaboration_id=collaboration_id)

@app.route('/legal/download/<filename>')
@login_required
def legal_download_file(filename):
    """Download uploaded file"""
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        logger.error(f"Error downloading file: {str(e)}")
        flash('Error downloading file', 'error')
        return redirect(url_for('dashboard'))


@app.route('/legal/access/<token>', methods=['GET', 'POST'])
@app.route('/legal/access/<token>/sig/<sig>', methods=['GET', 'POST'])
def legal_access(token, sig=None):
    """Handle legal representative access to collaboration"""
    try:
        logger.info("=== Starting legal_access route ===")
        logger.info(f"Received request - Token: {token}")
        logger.info(f"Request method: {request.method}")
        logger.info(f"Request args: {request.args}")
        logger.info(f"Route sig: {sig}")
        
        # Get signature from either route parameter or query param
        signature = sig or request.args.get('sig')
        if not signature:
            logger.error(f"No signature provided for legal access. Token: {token}")
            log_audit('error', 'legal_access', None, f"Missing signature for token: {token}")
            return redirect(url_for('legal_error', error_type='invalid'))
        
        # Import verify_access_token here to avoid circular imports
        from services.collaboration_notifications import verify_access_token
        
        # Verify token and get assignment
        logger.info("Calling verify_access_token...")
        assignment, collaboration_id = verify_access_token(token, signature)
        logger.info(f"verify_access_token returned - Assignment: {assignment and assignment.id}, Collab ID: {collaboration_id}")
        
        if not assignment:
            error_msg = f"Invalid token/signature combination. Token: {token}, Signature: {signature}"
            logger.error(error_msg)
            log_audit('error', 'legal_access', collaboration_id, error_msg)
            return redirect(url_for('legal_error', 
                                  error_type='invalid',
                                  collaboration_id=collaboration_id if collaboration_id else None))
        
        if assignment.is_completed:
            error_msg = f"Assignment {assignment.id} is completed for collaboration {assignment.collaboration_id}"
            logger.info(error_msg)
            log_audit('error', 'legal_access', assignment.collaboration_id, error_msg)
            return redirect(url_for('legal_error', error_type='expired'))
            
        if request.method == 'POST':
            try:
                logger.info("Processing legal response submission...")
                content = request.form.get('content')
                logger.info(f"Content: {content}")
                
                # Create comment event
                event = CollaborationEvent(
                    collaboration_id=assignment.collaboration_id,
                    event_type='comment',
                    content=content,
                    representative_id=assignment.representative_id
                )
                db.session.add(event)
                db.session.flush()  # Get event ID
                
                # Handle file attachment
                if 'attachment' in request.files:
                    file = request.files['attachment']
                    logger.info(f"Processing attachment: {file.filename}")
                    if file and file.filename:
                        result = save_collaboration_file(file, event.id)
                        if result and result[0]:  # Check if we got valid return values
                            stored_filename, original_filename = result
                            event.stored_filename = stored_filename
                            event.original_filename = original_filename
                            logger.info(f"Saved attachment: {original_filename} as {stored_filename}")
                        else:
                            logger.warning("Failed to save attachment")
                
                db.session.commit()
                
                # Send notification
                notify_collaboration_update(event)
                
                logger.info(f"Successfully added response for collaboration {assignment.collaboration_id}")
                return jsonify({
                    'success': True,
                    'message': 'Response submitted successfully'
                })
                
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error submitting response: {str(e)}", exc_info=True)
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500
        
        # For GET requests, show collaboration details
        logger.info("Rendering legal_access.html template...")
        return render_template('legal_access.html',
                             collaboration=assignment.collaboration,
                             representative=assignment.representative,
                             access_token=token,
                             signature=signature)
                             
    except Exception as e:
        error_msg = f"Error in legal access: {str(e)}"
        logger.error(error_msg, exc_info=True)
        log_audit('error', 'legal_access', None, error_msg)
        return redirect(url_for('legal_error', error_type='invalid'))
    
@app.route('/collaboration/<int:collab_id>/cancel', methods=['POST'])
@login_required
def cancel_collaboration(collab_id):
    try:
        collaboration = Collaboration.query.get_or_404(collab_id)
        collaboration.status = 'cancelled'
        
        # Add status change event
        event = CollaborationEvent(
            collaboration_id=collab_id,
            event_type='status_change',
            content='Collaboration cancelled',
            created_by_id=current_user.id
        )
        db.session.add(event)
        
        db.session.commit()
        log_audit('update', 'collaboration', collab_id, 'Cancelled collaboration')
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error cancelling collaboration: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/collaboration/assignment/<int:assignment_id>/resend', methods=['POST'])
@login_required
def resend_invitation(assignment_id):
    """Resend invitation email to legal representative"""
    try:
        assignment = CollaborationAssignment.query.get_or_404(assignment_id)
        collaboration = assignment.collaboration  # Get the collaboration from the assignment
        
        logger.info(f"Resending invitation to {assignment.representative.email}")
        
        # Import and use the correct send_collaboration_email function
        from collaboration_service import send_collaboration_email as send_email
        
        # Send email notification using the imported function
        success = send_email(collaboration, assignment)
        
        if success:
            logger.info(f"Successfully resent invitation to {assignment.representative.email}")
            return jsonify({
                'success': True,
                'message': 'Invitation email resent successfully'
            })
        else:
            raise Exception("Failed to send invitation email")
            
    except Exception as e:
        logger.error(f"Error resending invitation: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/collaboration/assignment/<int:assignment_id>', methods=['DELETE'])
@login_required
def remove_assignment(assignment_id):
    try:
        assignment = CollaborationAssignment.query.get_or_404(assignment_id)
        
        # Add event for removing representative
        event = CollaborationEvent(
            collaboration_id=assignment.collaboration_id,
            event_type='status_change',
            content=f'Removed representative: {assignment.representative.name}',
            created_by_id=current_user.id
        )
        db.session.add(event)
        
        # Delete the assignment
        db.session.delete(assignment)
        db.session.commit()
        
        log_audit('delete', 'collaboration_assignment', assignment_id, 
                 f'Removed representative {assignment.representative.name}')
        return '', 204
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error removing assignment: {str(e)}", exc_info=True)
        return str(e), 500

@app.route('/legal-office/<int:office_id>/representatives/json')
@login_required
def get_office_representatives(office_id):
    """Get legal representatives for office as JSON"""
    try:
        logger.info(f"Getting representatives for office {office_id}")
        office = LegalOffice.query.get_or_404(office_id)
        
        representatives = LegalRepresentative.query.filter_by(
            office_id=office_id,
            is_active=True
        ).order_by(LegalRepresentative.name).all()
        
        logger.info(f"Found {len(representatives)} active representatives")
        
        reps_data = [{
            'id': rep.id,
            'name': rep.name,
            'position': rep.position,
            'email': rep.email
        } for rep in representatives]
        
        return jsonify(reps_data)
        
    except Exception as e:
        logger.error(f"Error getting representatives: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/collaboration/<int:collab_id>/representatives', methods=['POST'])
@login_required
def add_representatives(collab_id):
    """Add representatives to collaboration"""
    try:
        collaboration = Collaboration.query.get_or_404(collab_id)
        data = request.get_json()
        representatives = data.get('representatives', [])
        
        logger.info(f"Adding representatives to collaboration {collab_id}: {representatives}")
        
        # Import the correct send_collaboration_email function
        from collaboration_service import send_collaboration_email
        
        for rep_id in representatives:
            representative = LegalRepresentative.query.get(rep_id)
            if not representative:
                continue
                
            # Generate access token and signature
            access_token = secrets.token_urlsafe(32)
            signature = secrets.token_hex(16)
            
            # Create assignment
            assignment = CollaborationAssignment(
                collaboration_id=collab_id,
                representative_id=rep_id,
                access_token=access_token,
                email_signature=signature
            )
            db.session.add(assignment)
            db.session.flush()  # Get assignment ID
            
            # Send email notification using the imported function
            if send_collaboration_email(collaboration, assignment):
                logger.info(f"Sent collaboration email to {representative.email}")
            else:
                logger.error(f"Failed to send collaboration email to {representative.email}")
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Representatives added successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding representatives: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/legal-office/<int:office_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_legal_office(office_id):
    """Edit an existing legal office"""
    office = LegalOffice.query.get_or_404(office_id)
    
    if request.method == 'POST':
        try:
            office.name = request.form['name']
            office.email = request.form['email']
            office.phone = request.form['phone']
            office.address = request.form['address']
            
            db.session.commit()
            
            log_audit('update', 'legal_office', office.id, f'Updated legal office: {office.name}')
            flash('Legal office updated successfully', 'success')
            return redirect(url_for('legal_offices'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error updating legal office: {str(e)}", exc_info=True)
            flash('Error updating legal office', 'error')
            
    return render_template('legal_office_form.html', office=office)

@app.route('/legal-office/<int:office_id>/deactivate', methods=['POST'])
@login_required
@admin_required
def deactivate_legal_office(office_id):
    """Deactivate (soft delete) a legal office"""
    try:
        office = LegalOffice.query.get_or_404(office_id)
        office.is_active = False
        
        # Also deactivate all representatives
        for rep in office.representatives:
            rep.is_active = False
        
        db.session.commit()
        
        log_audit('delete', 'legal_office', office_id, f'Deactivated legal office: {office.name}')
        return '', 204
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deactivating legal office: {str(e)}", exc_info=True)
        return str(e), 500

@app.route('/representative/<int:rep_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_representative(rep_id):
    """Edit an existing legal representative"""
    representative = LegalRepresentative.query.get_or_404(rep_id)
    office = representative.office
    
    if request.method == 'POST':
        try:
            representative.name = request.form['name']
            representative.email = request.form['email']
            representative.phone = request.form['phone']
            representative.position = request.form['position']
            
            db.session.commit()
            
            log_audit('update', 'legal_representative', rep_id, 
                     f'Updated representative: {representative.name}')
            flash('Representative updated successfully', 'success')
            return redirect(url_for('office_representatives', office_id=office.id))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error updating representative: {str(e)}", exc_info=True)
            flash('Error updating representative', 'error')
            
    return render_template('representative_form.html', 
                         office=office,
                         representative=representative)

@app.route('/representative/<int:rep_id>/deactivate', methods=['POST'])
@login_required
@admin_required
def deactivate_representative(rep_id):
    """Deactivate (soft delete) a legal representative"""
    try:
        representative = LegalRepresentative.query.get_or_404(rep_id)
        representative.is_active = False
        db.session.commit()
        
        log_audit('delete', 'legal_representative', rep_id, 
                 f'Deactivated representative: {representative.name}')
        return '', 204
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deactivating representative: {str(e)}", exc_info=True)
        return str(e), 500

@app.route('/collaboration/comment/<int:event_id>/edit', methods=['POST'])
@login_required
def edit_comment(event_id):
    """Edit a comment within 2 minutes of creation"""
    try:
        event = CollaborationEvent.query.get_or_404(event_id)
        
        # Check if user owns the comment
        if event.created_by_id != current_user.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
            
        # Check if within 2 minutes
        if datetime.utcnow() - event.created_at > timedelta(minutes=2):
            return jsonify({'success': False, 'error': 'Edit time expired'}), 400
            
        # Update content
        content = request.form.get('content')
        if not content:
            return jsonify({'success': False, 'error': 'Content required'}), 400
            
        event.content = content
        
        # Handle file attachment
        attachment_data = None
        
        # Remove existing attachment if requested
        if request.form.get('remove_attachment') == 'true' and event.file_path:
            old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], event.file_path)
            if os.path.exists(old_file_path):
                os.remove(old_file_path)
            event.file_path = None
            event.file_name = None
        
        # Add new attachment if provided
        if 'new_attachment' in request.files:
            file = request.files['new_attachment']
            if file and file.filename and allowed_file(file.filename):
                # Remove old file if exists
                if event.file_path:
                    old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], event.file_path)
                    if os.path.exists(old_file_path):
                        os.remove(old_file_path)
                
                # Save new file
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                
                event.file_path = filename
                event.file_name = file.filename
                
                attachment_data = {
                    'url': url_for('download_collaboration_file', event_id=event.id),
                    'name': file.filename
                }
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'content': event.content,
            'attachment': attachment_data
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error editing comment: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)})

# Update these configurations near the top of app.py, after creating the app
app.config.update(
    SERVER_NAME='localhost:5001',  # Update this for production
    APPLICATION_ROOT='/',
    PREFERRED_URL_SCHEME='http'    # Use 'https' in production
)

# Update the schedule_collaboration_email function
def schedule_collaboration_email(event_id):
    """Schedule email notification for 2 minutes after comment creation"""
    def send_delayed_email():
        with app.app_context():
            try:
                event = CollaborationEvent.query.get(event_id)
                if event:
                    success, recipients = notify_collaboration_update(event)
                    if success:
                        logger.info(f"Sent delayed notification for event {event_id}")
                        
                        # Update the event with notification recipients
                        event.notifications_sent = recipients
                        db.session.commit()
                        
                        # Update the UI via WebSocket or similar (future enhancement)
                    else:
                        logger.error(f"Failed to send delayed notification for event {event_id}")
            except Exception as e:
                logger.error(f"Error in delayed notification: {str(e)}", exc_info=True)
    
    # Schedule the job using local timezone
    local_tz = pytz.timezone('Asia/Jerusalem')  # Or your local timezone
    run_date = datetime.now(local_tz) + timedelta(minutes=2)
    
    job_id = f'notify_event_{event_id}'
    email_scheduler.add_job(
        func=send_delayed_email,
        trigger='date',
        run_date=run_date,
        id=job_id,
        name=f'Send notification for event {event_id}',
        replace_existing=True,
        misfire_grace_time=120  # Allow 2 minutes grace time for misfired jobs
    )
    logger.info(f"Scheduled notification for event {event_id} at {run_date}")

@app.route('/collaboration/assignment/<int:assignment_id>/revoke', methods=['POST'])
@login_required
def revoke_access_token(assignment_id):
    """Manually revoke an access token for testing"""
    try:
        assignment = CollaborationAssignment.query.get_or_404(assignment_id)
        
        # Generate new invalid tokens
        assignment.access_token = 'REVOKED_' + secrets.token_urlsafe(32)
        assignment.email_signature = 'REVOKED_' + secrets.token_hex(16)
        
        db.session.commit()
        logger.info(f"Access token revoked for assignment {assignment_id}")
        
        return jsonify({
            'success': True,
            'message': 'Access token revoked successfully'
        })
        
    except Exception as e:
        logger.error(f"Error revoking access token: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Add these imports at the top
from datetime import datetime, timedelta
import secrets

# Add these routes after other user-related routes
@app.route('/check-username')
def check_username():
    """Check if username is available"""
    username = request.args.get('username')
    if not username:
        return jsonify({'available': False})
    
    user = User.query.filter_by(username=username).first()
    return jsonify({'available': user is None})

@app.route('/set-password/<token>', methods=['GET', 'POST'])
def set_password(token):
    """Handle password setting for new users"""
    try:
        # Verify token and get user info
        user = User.query.filter_by(password_token=token).first()
        if not user or user.token_expiry < datetime.utcnow():
            flash('Invalid or expired password setup link', 'error')
            return redirect(url_for('login'))
        
        if request.method == 'POST':
            password = request.form.get('password')
            if password:
                user.set_password(password)
                user.password_token = None
                user.token_expiry = None
                db.session.commit()
                
                flash('Password set successfully. You can now login.', 'success')
                return redirect(url_for('login'))
            
        return render_template('set_password.html', username=user.username)
        
    except Exception as e:
        logger.error(f"Error in set_password: {str(e)}", exc_info=True)
        flash('Error setting password', 'error')
        return redirect(url_for('login'))

@app.route('/user/save', methods=['POST'])
@login_required
@admin_required
def save_user():
    """Create or update user"""
    try:
        user_id = request.form.get('user_id')
        name = request.form.get('name')
        username = request.form.get('username')
        email = request.form.get('email')
        user_type = request.form.get('user_type')  # Get user type from form
        set_password_by_user = request.form.get('set_password_by_user') == 'on'
        password = request.form.get('password')
        
        # Validate username uniqueness
        existing_user = User.query.filter_by(username=username).first()
        if existing_user and (not user_id or existing_user.id != int(user_id)):
            flash('Username already exists', 'error')
            return redirect(url_for('new_user' if not user_id else 'edit_user', user_id=user_id))
        
        if user_id:
            # Update existing user
            user = User.query.get_or_404(user_id)
            user.name = name
            user.username = username
            user.email = email
            user.user_type = user_type  # Update user type
            if password:
                user.set_password(password)
        else:
            # Create new user
            user = User(
                name=name, 
                username=username, 
                email=email,
                user_type=user_type  # Set user type
            )
            
            if set_password_by_user:
                # Generate password setup token
                token = secrets.token_urlsafe(32)
                user.password_token = token
                user.token_expiry = datetime.utcnow() + timedelta(hours=24)
                
                # Set a temporary password hash that will be updated when user sets their password
                temp_password = secrets.token_hex(16)
                user.set_password(temp_password)
                
                # Send password setup email
                setup_url = url_for('set_password', token=token, _external=True)
                html = render_template('emails/set_password.html',
                                    name=name,
                                    username=username,
                                    setup_url=setup_url)
                
                # Get sender email from settings
                enabled_provider = Settings.get_value('mail_provider_enabled', 'outlook')
                sender_email = Settings.get_value(f'{enabled_provider}_username', '')
                
                if not sender_email:
                    raise ValueError("No sender email configured. Please configure email settings first.")
                
                msg = Message(
                    subject='Set Your Password - Aman Contracts Management System',
                    sender=sender_email,
                    recipients=[email],
                    html=html
                )
                mail.send(msg)
            else:
                user.set_password(password)
            
            db.session.add(user)
        
        db.session.commit()
        flash(f"User {'updated' if user_id else 'created'} successfully", 'success')
        return redirect(url_for('users'))
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error saving user: {str(e)}", exc_info=True)
        flash('Error saving user', 'error')
        return redirect(url_for('users'))

@app.route('/users/<int:user_id>/send-password-email', methods=['POST'])
@login_required
@admin_required
def send_password_email(user_id):
    """Send password setup email to user"""
    try:
        user = User.query.get_or_404(user_id)
        
        # Generate new password setup token
        token = secrets.token_urlsafe(32)
        user.password_token = token
        user.token_expiry = datetime.utcnow() + timedelta(hours=24)
        
        # Get sender email from settings
        enabled_provider = Settings.get_value('mail_provider_enabled', 'outlook')
        sender_email = Settings.get_value(f'{enabled_provider}_username', '')
        
        if not sender_email:
            raise ValueError("No sender email configured. Please configure email settings first.")
        
        # Send password setup email
        setup_url = url_for('set_password', token=token, _external=True)
        html = render_template('emails/set_password.html',
                             name=user.name,
                             username=user.username,
                             setup_url=setup_url)
        
        msg = Message(
            subject='Set Your Password - Aman Contracts Management System',
            sender=sender_email,
            recipients=[user.email],
            html=html
        )
        mail.send(msg)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Password setup email sent successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error sending password email: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/representative/<int:rep_id>/send-password-email', methods=['POST'])
@login_required
@admin_required
def send_representative_password_email(rep_id):
    """Send password setup email to representative"""
    try:
        # Get representative
        representative = LegalRepresentative.query.get_or_404(rep_id)
        
        # Get or create user account
        user = User.query.filter_by(email=representative.email).first()
        if not user:
            # Create new user if doesn't exist
            user = User(
                name=representative.name,
                username=representative.email.split('@')[0],  # Use email prefix as username
                email=representative.email,
                user_type=UserType.LEGAL_REP.value  # Set user type here
            )
            # Set temporary password
            temp_password = secrets.token_hex(16)
            user.set_password(temp_password)
            db.session.add(user)
        
        # Generate new password token
        token = secrets.token_urlsafe(32)
        user.password_token = token
        user.token_expiry = datetime.utcnow() + timedelta(hours=24)
        
        # Get sender email from settings
        enabled_provider = Settings.get_value('mail_provider_enabled', 'outlook')
        sender_email = Settings.get_value(f'{enabled_provider}_username', '')
        
        if not sender_email:
            raise ValueError("No sender email configured. Please configure email settings first.")
        
        # Send password setup email
        setup_url = url_for('set_password', token=token, _external=True)
        html = render_template('emails/set_password.html',
                             name=user.name,
                             username=user.username,
                             setup_url=setup_url)
        
        msg = Message(
            subject='Set Your Password - Aman Contracts Management System',
            sender=sender_email,
            recipients=[user.email],
            html=html
        )
        mail.send(msg)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Password setup email sent successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error sending password email: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def create_app():
    app = Flask(__name__)
    # ... other initialization code ...
    
    with app.app_context():
        db.create_all()
        create_default_admin()  # Create default admin user
    
    return app

# Add this function to get the correct server name
def get_server_name():
    """Get the correct server name based on the request"""
    if request.environ.get('HTTP_X_FORWARDED_HOST'):
        return request.environ['HTTP_X_FORWARDED_HOST']
    elif request.environ.get('HTTP_HOST'):
        return request.environ['HTTP_HOST']
    elif request.environ.get('SERVER_NAME'):
        return request.environ['SERVER_NAME']
    return 'localhost'

# Update the main run section
if __name__ == '__main__':
    host = '0.0.0.0'  # Listen on all available interfaces
    
    try:
        # Use environment variable or default to 5000
        port = int(os.environ.get('FLASK_PORT', 5000))
        
        # Only search for port if the default is in use
        if not try_bind_port(port):
            logger.warning(f"Port {port} is in use, searching for next available port...")
            for p in range(port + 1, port + 100):
                if try_bind_port(p):
                    port = p
                    logger.info(f"Found available port: {port}")
                    # Store the found port in environment variable to be used by reloader
                    os.environ['FLASK_PORT'] = str(port)
                    port = int(os.environ.get('FLASK_PORT'))
                    break
            else:
                raise RuntimeError("Could not find an available port")
        
        # Initialize the application
        init_app()
        
        # Get local IP for display
        local_ip = get_local_ip()
        port = int(os.environ.get('FLASK_PORT', 5000))
        # Remove SERVER_NAME configuration completely
        app.config['SERVER_NAME'] = None
        BASE_URL=f"http://{local_ip}:{port}"
        app.config['BASE_URL'] = BASE_URL
        
        # Only show startup message for main process
        if not os.environ.get('WERKZEUG_RUN_MAIN'):
            message = f"""
Aman Contracts Management System is running!
Access URLs:
Local:     http://localhost:{port}
Internal:  http://{local_ip}:{port}
External:  http://{socket.gethostname()}:{port}
"""
            print(message)
            logger.info(message)
        
       
        
        # Add this after creating the app
        logger.info(f"Application starting with BASE_URL: {app.config['BASE_URL']}")
        
        # Important: Set these options for external access
        debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
        use_reloader = os.environ.get('FLASK_USE_RELOADER', 'False').lower() == 'true'

        app.run(
            host=host,
            port=port,
            debug=debug_mode,
            use_reloader=use_reloader,
            threaded=True
        )
        
    except (ValueError, RuntimeError) as e:
        logger.error(f"Failed to start server: {str(e)}")
        exit(1)

@app.context_processor
def inject_mail_config():
    """Make mail configuration status available to all templates"""
    try:
        is_configured = check_mail_configuration()
        logger.info(f"[inject_mail_config] Mail configuration status: {is_configured}")
        
        return {
            'mail_configured': is_configured
        }
    except Exception as e:
        logger.error(f"[inject_mail_config] Error checking mail config: {str(e)}")
        return {
            'mail_configured': False
        }

def get_server_url():
    """Get the server URL based on configuration or environment"""
    try:
        # Get local IP address
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        port = os.environ.get('FLASK_PORT', '5001')
        
        # Use environment variable or default to local IP
        server_url = os.environ.get('SERVER_URL', f'http://{local_ip}:{port}')
        
        logger.info(f"Using server URL: {server_url}")
        return server_url
    except Exception as e:
        logger.error(f"Error getting server URL: {str(e)}")
        return 'http://localhost:5001'  # Fallback

# Update app configuration
server_url = get_server_url()
parsed_url = urlparse(server_url)

app.config.update(
    SERVER_NAME=parsed_url.netloc,  # hostname:port
    PREFERRED_URL_SCHEME=parsed_url.scheme or 'http',
    APPLICATION_ROOT='/',
    # Add this to store the full URL
    SERVER_URL=server_url
)

# Update the notify_collaboration_update function in services/collaboration_notifications.py
def notify_collaboration_update(event):
    """Send email notifications for collaboration updates"""
    try:
        # Get server URL for links
        server_url = current_app.config.get('SERVER_URL') or get_server_url()
        
        # Get assignments that haven't been completed
        assignments = CollaborationAssignment.query.filter_by(
            collaboration_id=event.collaboration_id,
            is_completed=False
        ).all()
        
        if not assignments:
            logger.info("No pending assignments to notify")
            return True, []
            
        recipients = []
        for assignment in assignments:
            if assignment.representative.email:
                recipients.append(assignment.representative.email)
                
        if not recipients:
            logger.warning("No recipients found for notification")
            return True, []
            
        # Render email template with server URL
        html = render_template(
            'emails/collaboration_update.html',
            event=event,
            assignments=assignments,
            server_url=server_url
        )
        
        # Send email
        enabled_provider = Settings.get_value('mail_provider_enabled', 'outlook')
        sender_email = Settings.get_value(f'{enabled_provider}_username', '')
        
        msg = Message(
            subject=f'Update on Collaboration: {event.collaboration.title}',
            sender=sender_email,
            recipients=recipients,
            html=html
        )
        
        mail.send(msg)
        logger.info(f"Sent collaboration update email to {recipients}")
        
        return True, recipients
        
    except Exception as e:
        logger.error(f"Error sending collaboration update emails: {str(e)}", exc_info=True)
        return False, []

# Add configuration for file uploads
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'xls', 'xlsx'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create upload directories
os.makedirs(os.path.join(UPLOAD_FOLDER, 'contracts'), exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'chatFiles'), exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/uploads/<filename>')
@login_required
def download_file(filename):
    """Download uploaded file"""
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        logger.error(f"Error downloading file: {str(e)}")
        flash('Error downloading file', 'error')
        return redirect(url_for('dashboard'))

# Add this helper function
def save_attachment(file, collaboration_id, event_id):
    """Save file and create attachment record"""
    try:
        if not file or not file.filename:
            return None

        # Create chat files directory if it doesn't exist
        chat_files_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'chatFiles')
        os.makedirs(chat_files_dir, exist_ok=True)

        # Generate unique filename
        file_ext = os.path.splitext(file.filename)[1]
        stored_filename = f"collab_{collaboration_id}_event_{event_id}{file_ext}"
        file_path = os.path.join(chat_files_dir, stored_filename)

        # Save file
        file.save(file_path)

        # Create attachment record
        attachment = Attachment(
            collaboration_id=collaboration_id,
            event_id=event_id,
            original_filename=file.filename,
            stored_filename=stored_filename,
            file_size=os.path.getsize(file_path),
            mime_type=file.content_type
        )
        db.session.add(attachment)

        return attachment

    except Exception as e:
        logger.error(f"Error saving attachment: {str(e)}")
        return None

@app.route('/download/attachment/<int:attachment_id>')
@login_required
def download_attachment(attachment_id):
    """Download attachment file"""
    try:
        logger.info(f"Downloading attachment {attachment_id}")
        attachment = Attachment.query.get_or_404(attachment_id)
        
        # Get the correct directory based on attachment type
        if attachment.contract_id:
            upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'contracts')
        else:
            upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'chatFiles')
        
        file_path = os.path.join(upload_dir, attachment.stored_filename)
        logger.info(f"File path: {file_path}")
        
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            flash('The requested file could not be found', 'error')
            return redirect(url_for('dashboard'))
            
        logger.info(f"Sending file: {attachment.original_filename}")
        return send_from_directory(
            upload_dir,
            attachment.stored_filename,
            as_attachment=True,
            download_name=attachment.original_filename
        )
        
    except Exception as e:
        logger.error(f"Error downloading attachment: {str(e)}")
        flash('Error downloading file', 'error')
        return redirect(url_for('dashboard'))

@app.route('/check-mail-config', methods=['GET'])
@login_required
def check_mail_config_status():
    """Check mail configuration status"""
    try:
        is_configured = check_mail_configuration()
        logger.info(f"[check_mail_config_status] Mail configuration status: {is_configured}")
        return jsonify({
            'success': True,
            'mail_configured': is_configured
        })
    except Exception as e:
        logger.error(f"[check_mail_config_status] Error: {str(e)}")
        return jsonify({
            'success': False,
            'mail_configured': False,
            'error': str(e)
        }), 500
