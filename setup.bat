@echo off

:: Create virtual environment
python -m venv venv

:: Activate virtual environment
call venv\Scripts\activate

:: Upgrade pip
python -m pip install --upgrade pip

:: Install requirements
pip install -r requirements.txt

:: Create necessary directories
mkdir logs 2>nul
mkdir uploads\contracts uploads\chatFiles 2>nul

:: Create environment file
(
echo # Flask Configuration
echo FLASK_APP=app.py
echo FLASK_ENV=production
echo SECRET_KEY=%RANDOM%%RANDOM%%RANDOM%%RANDOM%
echo.
echo # Database Configuration
echo DATABASE_URL=sqlite:///app.db
echo.
echo # Mail Configuration
echo MAIL_SERVER=smtp.office365.com
echo MAIL_PORT=587
echo MAIL_USE_TLS=True
echo MAIL_USERNAME=your-email@aman.ps
echo MAIL_PASSWORD=your-password
echo.
echo # Server Configuration
echo SERVER_URL=https://contracts.aman.ps
echo UPLOAD_FOLDER=C:\inetpub\wwwroot\aman_contracts\uploads
echo MAX_CONTENT_LENGTH=16777216
echo.
echo # Security Settings
echo SESSION_COOKIE_SECURE=True
echo SESSION_COOKIE_HTTPONLY=True
echo SESSION_COOKIE_SAMESITE=Lax
echo PERMANENT_SESSION_LIFETIME=7200
) > .env

:: Initialize database
flask db upgrade

:: Create default admin user
flask create-admin

echo Setup completed successfully!