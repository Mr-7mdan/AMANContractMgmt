import multiprocessing
import os

# Server socket
bind = "unix:/tmp/aman_contracts.sock"
# bind = "0.0.0.0:8000"  # Alternative: bind to port instead of socket

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = 'sync'
worker_connections = 1000
timeout = 30
keepalive = 2

# Process naming
proc_name = 'aman_contracts'

# Logging
accesslog = '/var/log/aman_contracts/access.log'
errorlog = '/var/log/aman_contracts/error.log'
loglevel = 'info'

# SSL (if not using nginx)
# keyfile = '/etc/ssl/private/aman_contracts.key'
# certfile = '/etc/ssl/certs/aman_contracts.crt'

# Environment variables
raw_env = [
    f"FLASK_APP=app.py",
    f"FLASK_ENV=production",
]

# Security
limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190