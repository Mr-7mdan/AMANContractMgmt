from apscheduler.schedulers.background import BackgroundScheduler
from email_service import send_contract_notifications, send_periodic_report
from flask import current_app
from models import Settings
import json
import logging

logger = logging.getLogger(__name__)

# Create a global scheduler instance
scheduler = BackgroundScheduler()

def update_job_schedule(job_id, enabled):
    """Enable or disable a scheduled job"""
    job = scheduler.get_job(job_id)
    if job:
        if enabled:
            job.resume()
            logger.info(f"Job {job_id} resumed")
        else:
            job.pause()
            logger.info(f"Job {job_id} paused")

def init_scheduler(app):
    def check_expiry_notifications():
        with app.app_context():
            if Settings.get_value('expiry_notifications_enabled', 'true') == 'true':
                send_contract_notifications()
    
    def send_periodic_reports():
        with app.app_context():
            if Settings.get_value('periodic_notifications_enabled', 'false') == 'true':
                send_periodic_report()
    
    # Add expiry check job
    scheduler.add_job(
        check_expiry_notifications,
        'cron',
        hour=9,
        minute=0,
        id='expiry_check',
        name='Contract Expiry Check'
    )
    
    # Add periodic report job
    scheduler.add_job(
        send_periodic_reports,
        'cron',
        day=Settings.get_value('report_day', '1'),
        hour=9,
        minute=0,
        id='periodic_report',
        name='Periodic Contract Report'
    )
    
    # Set initial job states based on settings
    with app.app_context():
        expiry_enabled = Settings.get_value('expiry_notifications_enabled', 'true') == 'true'
        periodic_enabled = Settings.get_value('periodic_notifications_enabled', 'false') == 'true'
        
        update_job_schedule('expiry_check', expiry_enabled)
        update_job_schedule('periodic_report', periodic_enabled)
    
    if not scheduler.running:
        scheduler.start() 