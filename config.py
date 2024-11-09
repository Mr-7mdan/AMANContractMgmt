from datetime import timedelta
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # ... other config settings ...
    
    # Session config
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    SESSION_COOKIE_SECURE = False  # Set to True in production
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax' 
    
    # Add BASE_URL configuration
    BASE_URL = os.environ.get('BASE_URL', 'https://contracts.aman.ps')  # Set your production URL here