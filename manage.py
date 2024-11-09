import click
from flask.cli import FlaskGroup
from app import app
from models import db
from flask_migrate import Migrate
import pytest
import coverage
import os
import sys
from config import Config

# Initialize migrations
migrate = Migrate(app, db)

@click.group()
def cli():
    """Management script for the Aman Contracts application."""
    pass

@cli.command()
@click.option('--coverage', is_flag=True, help='Run tests with coverage report')
def test(coverage):
    """Run the unit tests."""
    # Add the application directory to PYTHONPATH
    sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
    
    if coverage:
        # Create coverage object
        cov = coverage.Coverage(
            branch=True,
            include=[
                '*.py',  # Include all Python files in root directory
                'app/*.py',  # Include all Python files in app directory
            ],
            omit=[
                'tests/*',  # Exclude test files
                'venv/*',   # Exclude virtual environment
                'migrations/*',  # Exclude migrations
                '*/__pycache__/*',  # Exclude cache files
                'manage.py'  # Exclude this file
            ]
        )
        
        # Start collecting coverage data
        cov.start()
    
    # Run tests
    result = pytest.main(['tests', '-v'])
    
    if coverage:
        # Generate coverage report
        cov.stop()
        cov.save()
        print('\nCoverage Summary:\n')
        cov.report()
        cov.html_report(directory='coverage_report')
        print('\nDetailed coverage report available at: coverage_report/index.html')
    
    return result

if __name__ == '__main__':
    cli() 