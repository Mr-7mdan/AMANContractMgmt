import secrets

def generate_access_token():
    """Generate a secure random token for legal access"""
    return secrets.token_urlsafe(32)

def generate_email_signature():
    """Generate a secure random signature for email verification"""
    return secrets.token_hex(16)