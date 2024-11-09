#!/bin/bash

echo "Starting Aman Contracts Management System..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Running setup..."
    ./setup.sh
fi

# Activate virtual environment
source venv/bin/activate

# Set Flask environment variables
export FLASK_APP=app.py
export FLASK_ENV=development
export FLASK_DEBUG=1

# Run the application
echo "Starting Flask application..."
python -m flask run --host=0.0.0.0 --port=5001 