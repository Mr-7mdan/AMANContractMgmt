#!/bin/bash

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install requirements
pip install -r requirements.txt

# Create necessary directories
mkdir -p logs uploads/contracts uploads/chatFiles

# Create environment file
cat > .env << EOL
# Flask Configuration
FLASK_APP=app.py
FLASK_ENV=production
SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')

# Database Configuration
DATABASE_URL=sqlite:///app.db

# Mail Configuration
MAIL_SERVER=smtp.office365.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@aman.ps
MAIL_PASSWORD=your-password

# Server Configuration
SERVER_URL=https://contracts.aman.ps
UPLOAD_FOLDER=/var/www/aman_contracts/uploads
MAX_CONTENT_LENGTH=16777216

# Security Settings
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax
PERMANENT_SESSION_LIFETIME=7200
EOL

# Initialize database
flask db upgrade

# Create default admin user
flask create-admin

echo "Setup completed successfully!"