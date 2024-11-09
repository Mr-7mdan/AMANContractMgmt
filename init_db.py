from flask import Flask
from config import Config
from models import db, User, Settings
import os

def init_database():
    # Create a new Flask app instance for initialization
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Create instance directory if it doesn't exist
    instance_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
    if not os.path.exists(instance_path):
        os.makedirs(instance_path)
        print(f"Created instance directory at {instance_path}")
    
    # Create uploads directory if it doesn't exist
    uploads_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    if not os.path.exists(uploads_path):
        os.makedirs(uploads_path)
        print(f"Created uploads directory at {uploads_path}")
    
    # Initialize the database
    db.init_app(app)
    
    with app.app_context():
        # Create all tables
        db.create_all()
        print("Created database tables")
        
        # Create default admin user
        default_username = 'aman'
        default_password = 'hamdan'
        
        user = User.query.filter_by(username=default_username).first()
        if not user:
            user = User(username=default_username)
            user.set_password(default_password)
            db.session.add(user)
            db.session.commit()
            print(f"Created default user with username: {default_username}")
        
        # Initialize default settings if not exists
        default_settings = {
            'notification_emails': 'contracts@aman.ps',
            'sender_email': 'contracts@aman.ps',
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': '587',
            'smtp_use_tls': 'true',
            'smtp_username': '',
            'smtp_password': ''
        }

        for key, value in default_settings.items():
            if not Settings.query.filter_by(key=key).first():
                setting = Settings(key=key, value=value)
                db.session.add(setting)
                print(f"Created default setting: {key}")
        
        db.session.commit()
        print("Database initialized successfully")

if __name__ == "__main__":
    init_database() 