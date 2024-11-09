#!/bin/bash

# Stop on any error
set -e

# Configuration
APP_NAME="aman_contracts"
APP_DIR="/var/www/$APP_NAME"
BACKUP_DIR="/var/www/backups/$APP_NAME"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create backup
echo "Creating backup..."
mkdir -p "$BACKUP_DIR"
if [ -d "$APP_DIR" ]; then
    tar -czf "$BACKUP_DIR/${APP_NAME}_${TIMESTAMP}.tar.gz" -C "$APP_DIR" .
fi

# Setup application directory
echo "Setting up application directory..."
mkdir -p "$APP_DIR"
chown www-data:www-data "$APP_DIR"

# Copy new files
echo "Copying new files..."
cp -r . "$APP_DIR/"

# Setup virtual environment
echo "Setting up virtual environment..."
cd "$APP_DIR"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Set permissions
echo "Setting permissions..."
chown -R www-data:www-data "$APP_DIR"
chmod -R 755 "$APP_DIR"

# Create necessary directories
mkdir -p "$APP_DIR/logs" "$APP_DIR/uploads/contracts" "$APP_DIR/uploads/chatFiles"
chown -R www-data:www-data "$APP_DIR/logs" "$APP_DIR/uploads"

# Database migrations
echo "Running database migrations..."
flask db upgrade

# Restart services
echo "Restarting services..."
systemctl restart nginx
systemctl restart aman_contracts

echo "Deployment completed successfully!" 