import os
from config import Config

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    
    # Use strong secret key in production
    SECRET_KEY = os.environ.get('SECRET_KEY')
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    
    # Mail settings
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    
    # Session/Cookie Settings
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 7200  # 2 hours
    
    # File Upload
    UPLOAD_FOLDER = '/var/www/aman_contracts/uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB