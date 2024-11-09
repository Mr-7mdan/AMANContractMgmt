# Aman Contracts Management System

A web-based system for managing contracts, tracking expiry dates, and sending automated notifications.

## Features

- Contract management with expiry tracking
- PDF attachment support
- Automated email notifications for expiring contracts
- Periodic contract status reports
- User management with role-based access
- Audit logging
- Email configuration
- Scheduler monitoring

## Prerequisites

Before you begin, ensure you have:

1. Python 3.9 or higher installed
2. Git installed
3. A Gmail account (for sending notifications)
4. IIS installed with CGI enabled
5. NSSM (Non-Sucking Service Manager) for Windows service management

## Installation Guide

### Setting up IIS

1. Open Server Manager
2. Add roles and features
3. Select "Web Server (IIS)"
4. Under Application Development Features, ensure these are checked:
   - CGI
   - URL Rewrite Module
   - Application Initialization

### Application Setup

1. Create application directory: