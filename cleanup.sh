#!/bin/bash

echo "Cleaning up project files..."

# Remove Python cache files
echo "Removing Python cache files..."
find . -type f -name "*.pyc" -delete
find . -type d -name "__pycache__" -exec rm -r {} +

# Remove logs
echo "Removing logs..."
rm -rf logs/*
touch logs/.gitkeep

# Remove uploads
echo "Removing uploads..."
rm -rf uploads/*
mkdir -p uploads/contracts uploads/chatFiles
touch uploads/contracts/.gitkeep uploads/chatFiles/.gitkeep

# Remove database
echo "Removing database files..."
rm -f app.db

# Remove environment files
echo "Removing environment files..."
rm -f .env

# Remove IDE files
echo "Removing IDE files..."
rm -rf .vscode/
rm -rf .idea/

# Remove test files
echo "Removing test files..."
rm -rf tests/
rm -f pytest.ini
rm -rf .pytest_cache/
rm -rf htmlcov/
rm -f .coverage

# Remove any temporary files
echo "Removing any temporary files..."
rm -f *.log
rm -f *.tmp

echo "Cleanup completed successfully!" 