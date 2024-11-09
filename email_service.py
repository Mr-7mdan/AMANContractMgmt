from flask import render_template, current_app
from flask_mail import Mail, Message
from datetime import datetime, timedelta
import json
from models import Contract, NotificationHistory, db, Settings, MAIL_PROVIDERS
import logging
import re
from utils.audit import log_audit

logger = logging.getLogger(__name__)

mail = Mail()

def validate_email(email):
    """Validate email format"""
    if not email:
        return False
        
    # Remove any whitespace
    email = email.strip()
    
    # Basic email pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    is_valid = bool(re.match(pattern, email))
    
    if not is_valid:
        logger.warning(f"Invalid email format: {email}")
    
    return is_valid

def format_email_list(emails_str):
    """Convert comma/semicolon-separated email string to list of valid emails"""
    if not emails_str:
        return []
    
    # Split by both comma and semicolon and clean each email
    emails = []
    for separator in [',', ';']:
        if separator in emails_str:
            emails.extend([email.strip() for email in emails_str.split(separator)])
    
    # If no separators found, treat as single email
    if not emails:
        emails = [emails_str.strip()]
    
    # Filter out empty strings and validate emails
    valid_emails = [email for email in emails if email and validate_email(email)]
    
    if not valid_emails:
        logger.warning(f"No valid emails found in: {emails_str}")
    else:
        logger.info(f"Valid emails found: {valid_emails}")
    
    return valid_emails

def setup_mail(app):
    """Configure Flask-Mail based on settings"""
    try:
        # Get enabled provider
        enabled_provider = Settings.get_value('mail_provider_enabled', 'outlook')
        logger.info(f"Setting up mail for provider: {enabled_provider}")
        
        if not enabled_provider:
            logger.warning("No mail provider enabled")
            return
            
        # Get provider settings
        username = Settings.get_value(f'{enabled_provider}_username', '')
        password = Settings.get_value(f'{enabled_provider}_password', '')
        
        logger.info(f"Provider settings - Username exists: {bool(username)}, Password exists: {bool(password)}")
        
        if not username or not password:
            logger.warning(f"Email settings incomplete for {enabled_provider} - Username exists: {bool(username)}, Password exists: {bool(password)}")
            return
            
        # Configure based on provider
        if enabled_provider == 'outlook':
            logger.info("Configuring Outlook settings")
            app.config.update(
                MAIL_SERVER='smtp.office365.com',
                MAIL_PORT=587,
                MAIL_USE_TLS=True,
                MAIL_USERNAME=username,
                MAIL_PASSWORD=password,
                MAIL_DEFAULT_SENDER=username
            )
            logger.info("Outlook configuration complete")
        elif enabled_provider == 'gmail':
            app.config.update(
                MAIL_SERVER='smtp.gmail.com',
                MAIL_PORT=587,
                MAIL_USE_TLS=True,
                MAIL_USE_SSL=False
            )
        elif enabled_provider == 'exchange':
            exchange_server = Settings.get_value('exchange_server', '')
            if not exchange_server:
                logger.error("Exchange server URL not configured")
                return
                
            app.config.update(
                MAIL_SERVER=exchange_server,
                MAIL_PORT=587,
                MAIL_USE_TLS=True,
                MAIL_USE_SSL=False
            )
        
        app.config.update(
            MAIL_DEFAULT_SENDER=username  # Use authenticated email as sender
        )
        
        # Validate settings for enabled provider
        if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
            logger.warning(f"Email settings incomplete for {enabled_provider}")
        
        mail.init_app(app)
    except Exception as e:
        logger.error(f"Error setting up mail: {str(e)}")

def get_urgency_level(days_remaining):
    if days_remaining <= 15:
        return '🔴 Critical'
    elif days_remaining <= 30:
        return '🟠 High'
    elif days_remaining <= 60:
        return '🟡 Medium'
    else:
        return '🟢 Low'

def send_contract_notifications():
    app = current_app._get_current_object()
    with app.app_context():
        try:
            # Get notification periods from settings
            notification_periods_raw = Settings.get_value('notification_periods', '[]')
            notification_periods = json.loads(notification_periods_raw)
            
            logger.info(f"Notification periods from DB: {notification_periods}")
            
            # Convert periods to flags
            notify_one_week = "One Week" in notification_periods
            notify_two_weeks = "Two Weeks" in notification_periods
            notify_one_month = "One Month" in notification_periods
            notify_two_months = "Two Months" in notification_periods
            
            logger.info(f"Processed notification settings - One Week: {notify_one_week}, "
                       f"Two Weeks: {notify_two_weeks}, One Month: {notify_one_month}, "
                       f"Two Months: {notify_two_months}")

            # Get contracts expiring within the next month
            one_month_from_now = datetime.now().date() + timedelta(days=30)
            expiring_contracts = Contract.query.filter(
                Contract.is_active == True,
                Contract.expiry_date <= one_month_from_now
            ).all()

            logger.info(f"Found {len(expiring_contracts)} contracts to check for notifications")

            if not expiring_contracts:
                logger.info("No contracts found that need notifications")
                return "No contracts found that need notifications", False

            # Prepare all contracts that need notification
            contracts_to_notify = []
            contract_ids = []
            for contract in expiring_contracts:
                days_until_expiry = (contract.expiry_date - datetime.now().date()).days
                notify = False
                
                # Check against enabled notification periods
                if notify_one_week and days_until_expiry <= 7:
                    notify = True
                elif notify_two_weeks and days_until_expiry <= 14:
                    notify = True
                elif notify_one_month and days_until_expiry <= 30:
                    notify = True
                elif notify_two_months and days_until_expiry <= 60:
                    notify = True

                logger.info(f"Contract: {contract.name}, Days until expiry: {days_until_expiry}, Should notify: {notify}")
                
                if notify:
                    contracts_to_notify.append({
                        'name': contract.name,
                        'party_name': contract.party_name,
                        'expiry_date': contract.expiry_date.strftime('%Y-%m-%d'),
                        'days_remaining': days_until_expiry,
                        'urgency': get_urgency_level(days_until_expiry)
                    })
                    contract_ids.append(contract.id)

            if not contracts_to_notify:
                # Log the "no notifications needed" case
                notification = NotificationHistory(
                    contract_id=0,
                    notification_type='expiry',
                    recipients=json.dumps([]),
                    subject="No contracts require notification at this time",
                    message="No contracts require notification at this time",
                    status='Success'
                )
                db.session.add(notification)
                db.session.commit()
                logger.info("No contracts require notification at this time")
                return "No contracts require notification at this time", False

            try:
                # Render email template with all contracts
                email_content = render_template(
                    'emails/contract_notification.html',
                    contracts=contracts_to_notify,
                    now=datetime.now()
                )

                # Get and validate recipient emails
                recipients = format_email_list(Settings.get_value('notification_emails', ''))
                if not recipients:
                    error_msg = "No valid notification recipients configured"
                    logger.error(error_msg)
                    return error_msg, False

                # Create and send single email with all contracts
                msg = Message(
                    subject=f'Contract Expiration Notification - {len(contracts_to_notify)} Contracts Expiring',
                    sender=app.config['MAIL_USERNAME'],  # Use authenticated email
                    recipients=recipients,
                    html=email_content
                )

                mail.send(msg)
                logger.info(f"Sent combined notification email for {len(contracts_to_notify)} contracts")

                # Create notification record
                notification = NotificationHistory(
                    contract_id=contract_ids[0],
                    notification_type='expiry',
                    recipients=json.dumps(recipients),
                    subject=f'Contract Expiration Notification - {len(contracts_to_notify)} Contracts Expiring',
                    message=email_content,
                    status='sent'
                )
                db.session.add(notification)
                db.session.commit()

                return f"Notification sent successfully for {len(contracts_to_notify)} contracts", True

            except Exception as e:
                error_msg = f"Error sending notification email: {str(e)}"
                logger.error(error_msg, exc_info=True)
                
                # Log failed notification attempt
                notification = NotificationHistory(
                    contract_id=contract_ids[0],
                    notification_type='expiry',
                    recipients=json.dumps(recipients),
                    subject=f'Contract Expiration Notification - {len(contracts_to_notify)} Contracts Expiring',
                    message=str(e),
                    status='error',
                    error=str(e)
                )
                db.session.add(notification)
                db.session.commit()
                
                return error_msg, False

        except Exception as e:
            error_msg = f"Error in notification process: {str(e)}"
            logger.error(error_msg, exc_info=True)
            
            # Log the error in notification history
            try:
                notification = NotificationHistory(
                    contract_id=0,
                    notification_type='expiry',
                    recipients=json.dumps([]),
                    subject=f"System Error",
                    message=str(e),
                    status='error',
                    error=str(e)
                )
                db.session.add(notification)
                db.session.commit()
            except Exception as db_error:
                logger.error(f"Failed to log notification error: {str(db_error)}", exc_info=True)
            
            return error_msg, False

def send_periodic_report():
    """Send periodic report of all contracts"""
    try:
        # Get the current mail provider settings
        provider = Settings.get_value('mail_provider', 'outlook')
        username = Settings.get_value(f'{provider}_username')
        notification_emails = Settings.get_value('notification_emails')

        if not username or not notification_emails:
            logger.warning("Email settings are incomplete")
            return "Email settings are incomplete", False

        # Get all active contracts
        contracts = Contract.query.filter_by(is_active=True).all()
        
        # Create the report content
        html_content = create_report_content(contracts)
        
        # Get list of recipients
        recipients = format_email_list(notification_emails)
        if not recipients:
            error_msg = "No valid notification recipients configured"
            logger.error(error_msg)
            return error_msg, False
        
        # Create the email message with HTML content
        msg = Message(
            subject='Aman Contracts System - Periodic Report',
            sender=username,
            recipients=recipients,
            html=html_content  # Use HTML content instead of plain text
        )
        
        # Send the email
        mail.send(msg)
        
        # Log success
        logger.info(f"Sent periodic report to {recipients}")
        log_audit('email', 'periodic_report', None, f'Sent periodic report to {recipients}')
        
        # Create notification history entry
        notification = NotificationHistory(
            contract_id=0,
            notification_type='periodic_report',
            recipients=json.dumps(recipients),
            subject='Aman Contracts System - Periodic Report',
            message=html_content,
            status='sent'
        )
        db.session.add(notification)
        db.session.commit()
        
        return f"Periodic report sent successfully to {', '.join(recipients)}", True
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error sending periodic report: {error_msg}", exc_info=True)
        
        # Create failed notification history entry
        notification = NotificationHistory(
            contract_id=0,
            notification_type='periodic_report',
            recipients=json.dumps([]),
            subject="Failed to generate periodic report",
            message=str(e),
            status='error',
            error=str(e)
        )
        db.session.add(notification)
        db.session.commit()
        
        return f"Error sending periodic report: {error_msg}", False

def create_report_content(contracts):
    """Create the content for the periodic report"""
    # Create HTML content
    html_content = """
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .header { background: #0f203c; color: white; padding: 20px; text-align: center; }
            .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
            .expired { background-color: #ffe6e6; }
            .critical { background-color: #fff3e6; }
            .warning { background-color: #fffbe6; }
            .good { background-color: #e6ffe6; }
            .summary { background-color: #f5f5f5; padding: 15px; margin-top: 20px; }
            table { width: 100%; border-collapse: collapse; margin: 10px 0; }
            th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background-color: #f2f2f2; }
            .status-indicator { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 5px; }
            .status-expired { background-color: #ff4444; }
            .status-critical { background-color: #ffa500; }
            .status-warning { background-color: #ffdd00; }
            .status-good { background-color: #44ff44; }
        </style>
    </head>
    <body>
        <div class="header">
            <h2>Aman Contracts System - Periodic Report</h2>
            <p>Generated on: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
        </div>
    """

    # Group contracts by status
    expired = []
    critical = []
    warning = []
    good = []
    
    for contract in contracts:
        if contract.status == 'expired':
            expired.append(contract)
        elif contract.status == 'critical':
            critical.append(contract)
        elif contract.status == 'warning':
            warning.append(contract)
        else:
            good.append(contract)

    # Add expired contracts section
    if expired:
        html_content += """
        <div class="section expired">
            <h3><span class="status-indicator status-expired"></span>Expired Contracts</h3>
            <table>
                <tr>
                    <th>Contract Name</th>
                    <th>Party Name</th>
                    <th>Days Expired</th>
                    <th>Expiry Date</th>
                </tr>
        """
        for contract in expired:
            html_content += f"""
                <tr>
                    <td>{contract.name}</td>
                    <td>{contract.party_name}</td>
                    <td>{abs(contract.days_until_expiry)} days ago</td>
                    <td>{contract.expiry_date.strftime('%Y-%m-%d')}</td>
                </tr>
            """
        html_content += "</table></div>"

    # Add critical contracts section
    if critical:
        html_content += """
        <div class="section critical">
            <h3><span class="status-indicator status-critical"></span>Critical Contracts (Expiring within 7 days)</h3>
            <table>
                <tr>
                    <th>Contract Name</th>
                    <th>Party Name</th>
                    <th>Days Until Expiry</th>
                    <th>Expiry Date</th>
                </tr>
        """
        for contract in critical:
            html_content += f"""
                <tr>
                    <td>{contract.name}</td>
                    <td>{contract.party_name}</td>
                    <td>{contract.days_until_expiry} days</td>
                    <td>{contract.expiry_date.strftime('%Y-%m-%d')}</td>
                </tr>
            """
        html_content += "</table></div>"

    # Add warning contracts section
    if warning:
        html_content += """
        <div class="section warning">
            <h3><span class="status-indicator status-warning"></span>Warning Contracts (Expiring within 30 days)</h3>
            <table>
                <tr>
                    <th>Contract Name</th>
                    <th>Party Name</th>
                    <th>Days Until Expiry</th>
                    <th>Expiry Date</th>
                </tr>
        """
        for contract in warning:
            html_content += f"""
                <tr>
                    <td>{contract.name}</td>
                    <td>{contract.party_name}</td>
                    <td>{contract.days_until_expiry} days</td>
                    <td>{contract.expiry_date.strftime('%Y-%m-%d')}</td>
                </tr>
            """
        html_content += "</table></div>"

    # Add good standing contracts section
    if good:
        html_content += """
        <div class="section good">
            <h3><span class="status-indicator status-good"></span>Contracts in Good Standing</h3>
            <table>
                <tr>
                    <th>Contract Name</th>
                    <th>Party Name</th>
                    <th>Days Until Expiry</th>
                    <th>Expiry Date</th>
                </tr>
        """
        for contract in good:
            html_content += f"""
                <tr>
                    <td>{contract.name}</td>
                    <td>{contract.party_name}</td>
                    <td>{contract.days_until_expiry} days</td>
                    <td>{contract.expiry_date.strftime('%Y-%m-%d')}</td>
                </tr>
            """
        html_content += "</table></div>"

    # Add summary section
    html_content += f"""
        <div class="summary">
            <h3>Summary</h3>
            <table>
                <tr>
                    <td>Total Contracts:</td>
                    <td>{len(contracts)}</td>
                </tr>
                <tr>
                    <td>Expired:</td>
                    <td>{len(expired)}</td>
                </tr>
                <tr>
                    <td>Critical:</td>
                    <td>{len(critical)}</td>
                </tr>
                <tr>
                    <td>Warning:</td>
                    <td>{len(warning)}</td>
                </tr>
                <tr>
                    <td>Good Standing:</td>
                    <td>{len(good)}</td>
                </tr>
            </table>
        </div>
    </body>
    </html>
    """
    
    return html_content

def test_email_settings():
    """Test email settings by sending a test email"""
    try:
        # Get current provider settings
        mail_provider = Settings.get_value('mail_provider_enabled', 'outlook')
        smtp_username = Settings.get_value(f'{mail_provider}_username', '')
        
        logger.info(f"Testing email settings for provider: {mail_provider}")
        logger.info(f"Using email address: {smtp_username}")
        
        if not smtp_username:
            error_msg = f"Email settings are incomplete: No username configured for {MAIL_PROVIDERS[mail_provider]}"
            logger.error(error_msg)
            return error_msg, False

        # Create test message using provider-specific settings
        msg = Message(
            subject=f"Test Email from Aman Contracts System ({MAIL_PROVIDERS[mail_provider]})",
            sender=smtp_username,  # Use authenticated email as sender
            recipients=[smtp_username]  # Send to self for testing
        )
        msg.body = f"This is a test email to verify your {MAIL_PROVIDERS[mail_provider]} settings."

        # Try to send
        logger.info(f"Attempting to send test email via {MAIL_PROVIDERS[mail_provider]}")
        mail.send(msg)
        
        success_msg = f"Test email sent successfully using {MAIL_PROVIDERS[mail_provider]}!"
        logger.info(success_msg)
        return success_msg, True
        
    except Exception as e:
        error_msg = str(e)
        provider_name = MAIL_PROVIDERS[mail_provider]
        
        # Provide user-friendly error messages
        if "Client not authenticated" in error_msg:
            error_msg = f"Authentication failed for {provider_name}. Please check your credentials."
        elif "SendAsDenied" in error_msg:
            error_msg = f"Permission denied: Your {provider_name} account is not allowed to send as another address."
        elif "invalid login" in error_msg.lower():
            error_msg = f"Invalid login credentials. Please check your {provider_name} email and password."
        elif "ssl" in error_msg.lower():
            error_msg = f"SSL/TLS connection failed. Please check your {provider_name} server settings."
        
        logger.error(f"Error testing {provider_name} email settings: {error_msg}")
        return f"Failed to send test email using {provider_name}: {error_msg}", False