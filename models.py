import logging
logger = logging.getLogger(__name__)

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from enum import Enum

# Initialize SQLAlchemy with no settings
db = SQLAlchemy()

# Move this before the User class
class UserType(Enum):
    ADMIN = 'Admin'
    STANDARD = 'Standard User'
    LEGAL_REP = 'Legal Representative'

    @classmethod
    def choices(cls):
        return [(type.value, type.value) for type in cls]

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), nullable=True)
    password_hash = db.Column(db.String(120), nullable=False)
    password_token = db.Column(db.String(100), unique=True, nullable=True)
    token_expiry = db.Column(db.DateTime, nullable=True)
    user_type = db.Column(db.String(50), nullable=False, default=UserType.STANDARD.value)
    
    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        """Check password against hash"""
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        """Check if user is admin"""
        return self.user_type == UserType.ADMIN.value

    def __repr__(self):
        return f'<User {self.username}>'

class Contract(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    party_name = db.Column(db.String(200), nullable=False)
    signing_date = db.Column(db.Date, nullable=False)
    validity_days = db.Column(db.Integer, nullable=False)
    expiry_date = db.Column(db.Date, nullable=False)
    notify_period = db.Column(db.String(20), nullable=False, default='One Week')
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    collaborations = db.relationship('Collaboration', back_populates='contract')

    def get_latest_expiry_date(self):
        """
        Calculate the actual final expiry date considering all overlaps
        between the contract and its extensions
        """
        # Start with the contract's original period
        periods = [(self.signing_date, self.expiry_date)]
        
        # Add all extensions
        for ext in sorted(self.extensions, key=lambda x: x.effective_date):
            periods.append((ext.effective_date, ext.expiry_date))
        
        if not periods:
            return self.expiry_date
            
        # Merge overlapping periods
        merged = []
        current_start, current_end = periods[0]
        
        for start, end in sorted(periods[1:]):
            if start <= current_end:
                # Periods overlap, extend the current period if needed
                current_end = max(current_end, end)
            else:
                # No overlap, add the current period and start a new one
                merged.append((current_start, current_end))
                current_start, current_end = start, end
        
        # Add the last period
        merged.append((current_start, current_end))
        
        # Return the latest end date from merged periods
        return max(end for _, end in merged)

    @property
    def days_until_expiry(self):
        """Calculate days remaining until contract expires using the actual final expiry date"""
        if self.get_latest_expiry_date():
            delta = self.get_latest_expiry_date() - date.today()
            return delta.days
        return None

    @property
    def status(self):
        """Return contract status based on days until expiry"""
        if not self.days_until_expiry:
            return 'unknown'
        if self.days_until_expiry <= 0:
            return 'expired'
        if self.days_until_expiry <= 7:
            return 'critical'
        if self.days_until_expiry <= 30:
            return 'warning'
        return 'good'

    def __repr__(self):
        return f'<Contract {self.name}>'

class Attachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    collaboration_id = db.Column(db.Integer, db.ForeignKey('collaboration.id'), nullable=True)
    event_id = db.Column(db.Integer, db.ForeignKey('collaboration_event.id'), nullable=True)
    contract_id = db.Column(db.Integer, db.ForeignKey('contract.id'), nullable=True)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer)
    mime_type = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Relationships
    collaboration = db.relationship('Collaboration', backref='attachments')
    event = db.relationship('CollaborationEvent', backref='attachments')
    contract = db.relationship('Contract', backref='attachments')

    def __repr__(self):
        return f'<Attachment {self.id} - {self.original_filename}>'

class NotificationHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contract_id = db.Column(db.Integer, db.ForeignKey('contract.id'), nullable=False)
    notification_type = db.Column(db.String(50), nullable=False)
    recipients = db.Column(db.Text, nullable=False)  # Store as JSON string
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='sent')
    error = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Relationship
    contract = db.relationship('Contract', backref='notifications', lazy=True)

    def __repr__(self):
        return f'<NotificationHistory {self.id} - {self.notification_type}>'

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(50), nullable=False)
    entity_type = db.Column(db.String(50), nullable=False)
    entity_id = db.Column(db.Integer)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.Column(db.String(80))

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(128), unique=True, nullable=False)
    value = db.Column(db.String(512))

    @staticmethod
    def get_value(key, default=None):
        setting = Settings.query.filter_by(key=key).first()
        return setting.value if setting else default

    @staticmethod
    def set_value(key, value):
        setting = Settings.query.filter_by(key=key).first()
        if setting:
            setting.value = value
        else:
            setting = Settings(key=key, value=value)
            db.session.add(setting)
        db.session.commit()

# Add these to the Settings model's default settings
NOTIFICATION_TYPES = {
    'expiry': 'Expiry Notifications',
    'periodic': 'Periodic Contract Reports'
}

PERIODIC_FREQUENCIES = {
    'monthly': 'Monthly',
    'quarterly': 'Quarterly',
    'semi_annual': 'Semi-Annual',
    'annual': 'Annual'
}

# Add to the Settings model's class variables
MAIL_PROVIDERS = {
    'outlook': 'Microsoft 365',
    'gmail': 'Gmail',
    'exchange': 'Exchange Server'
}

# Add these settings to default settings in init_db.py
DEFAULT_MAIL_SETTINGS = {
    'mail_provider': 'outlook',  # Default to Microsoft 365
    'mail_provider_enabled': 'outlook',  # Track which provider is enabled
    'exchange_server': '',     # For Exchange server URL
    'gmail_username': '',      # Gmail-specific email
    'outlook_username': '',    # Microsoft 365-specific email
    'exchange_username': '',   # Exchange-specific email
    'gmail_password': '',      # Gmail-specific password
    'outlook_password': '',    # Microsoft 365-specific password
    'exchange_password': '',   # Exchange-specific password
}

# Add these new models

class LegalOffice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    address = db.Column(db.String(500))
    phone = db.Column(db.String(50))
    email = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    representatives = db.relationship('LegalRepresentative', backref='office', lazy=True)

class LegalRepresentative(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    office_id = db.Column(db.Integer, db.ForeignKey('legal_office.id'), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(50))
    position = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class Collaboration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    contract_id = db.Column(db.Integer, db.ForeignKey('contract.id'))
    office_id = db.Column(db.Integer, db.ForeignKey('legal_office.id'), nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='open')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Relationships
    contract = db.relationship('Contract', back_populates='collaborations')
    office = db.relationship('LegalOffice')
    created_by = db.relationship('User')
    events = db.relationship('CollaborationEvent', back_populates='collaboration')
    assignments = db.relationship('CollaborationAssignment', backref='collaboration')

class CollaborationEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    collaboration_id = db.Column(db.Integer, db.ForeignKey('collaboration.id'), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    representative_id = db.Column(db.Integer, db.ForeignKey('legal_representative.id'))
    stored_filename = db.Column(db.String(255))
    original_filename = db.Column(db.String(255))
    parent_id = db.Column(db.Integer, db.ForeignKey('collaboration_event.id'))

    # Relationships
    collaboration = db.relationship('Collaboration', back_populates='events')
    created_by = db.relationship('User')
    representative = db.relationship('LegalRepresentative')
    replies = db.relationship('CollaborationEvent', 
                            backref=db.backref('parent', remote_side=[id]),
                            lazy='dynamic')

class CollaborationAssignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    collaboration_id = db.Column(db.Integer, db.ForeignKey('collaboration.id'), nullable=False)
    representative_id = db.Column(db.Integer, db.ForeignKey('legal_representative.id'), nullable=False)
    access_token = db.Column(db.String(200), unique=True, nullable=False)
    email_signature = db.Column(db.String(200), unique=True, nullable=False)
    is_completed = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    
    # Relationships
    representative = db.relationship('LegalRepresentative')

# Add this after the UserType enum class definition
def create_default_admin():
    """Create default admin user if it doesn't exist"""
    try:
        admin = User.query.filter_by(username='aman').first()
        if admin:
            # Update existing admin user to ensure correct user type
            if admin.user_type != UserType.ADMIN.value:
                admin.user_type = UserType.ADMIN.value
                db.session.commit()
                logger.info("Updated default admin user type")
        else:
            # Create new admin user
            admin = User(
                name='Aman Admin',
                username='aman',
                email='admin@aman.ps',
                user_type=UserType.ADMIN.value
            )
            admin.set_password('admin')  # Set a default password
            db.session.add(admin)
            db.session.commit()
            logger.info("Created default admin user")

            logger.info(f"Created user type is {admin.user_type}")
            
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating/updating default admin: {str(e)}")