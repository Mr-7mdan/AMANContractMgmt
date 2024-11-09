@echo off
echo Starting Aman Contracts Management System...

:: Check if virtual environment exists
if not exist "venv" (
    echo Virtual environment not found. Running setup...
    call setup.bat
)

:: Activate virtual environment
call venv\Scripts\activate

:: Set Flask environment variables
set FLASK_APP=app.py
set FLASK_ENV=development
set FLASK_DEBUG=1

:: Run the application
echo Starting Flask application...
python -m flask run --host=0.0.0.0 --port=5001

pause 