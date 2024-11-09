from flask import url_for
from models import Collaboration, CollaborationEvent
from sqlalchemy import or_

def get_collaboration_notifications(user_id):
    """Get collaboration notifications for dashboard"""
    # Get recent events from user's collaborations
    notifications = []
    
    # Collaborations created by user
    collaborations = Collaboration.query.filter_by(created_by_id=user_id).all()
    
    for collab in collaborations:
        # Get latest event
        latest_event = collab.events[0] if collab.events else None
        
        if latest_event:
            notifications.append({
                'type': 'collaboration',
                'subtype': latest_event.event_type,
                'title': collab.title,
                'message': f'New {latest_event.event_type} from {latest_event.representative.name if latest_event.representative else latest_event.created_by.name}',
                'timestamp': latest_event.created_at,
                'url': url_for('view_collaboration', collab_id=collab.id),
                'status': collab.status
            })
            
        # Check for pending assignments
        pending_count = sum(1 for a in collab.assignments if not a.is_completed)
        if pending_count > 0:
            notifications.append({
                'type': 'collaboration',
                'subtype': 'pending',
                'title': collab.title,
                'message': f'{pending_count} pending responses from legal representatives',
                'timestamp': collab.updated_at,
                'url': url_for('view_collaboration', collab_id=collab.id),
                'status': 'pending'
            })
    
    return sorted(notifications, key=lambda x: x['timestamp'], reverse=True) 