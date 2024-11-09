# Configuration
$AppName = "aman_contracts"
$IISPath = "C:\inetpub\wwwroot\$AppName"
$BackupPath = "C:\inetpub\backups\$AppName"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Create backup
Write-Host "Creating backup..."
if (Test-Path $IISPath) {
    New-Item -ItemType Directory -Force -Path $BackupPath
    Compress-Archive -Path "$IISPath\*" -DestinationPath "$BackupPath\${AppName}_${Timestamp}.zip"
}

# Setup application directory
Write-Host "Setting up application directory..."
New-Item -ItemType Directory -Force -Path $IISPath

# Copy new files
Write-Host "Copying new files..."
Copy-Item -Path ".\*" -Destination $IISPath -Recurse -Force

# Setup virtual environment
Write-Host "Setting up virtual environment..."
Set-Location $IISPath
python -m venv venv
.\venv\Scripts\Activate.ps1
python3.9 -m pip install pip
pip install -r requirements.txt

# Create necessary directories
Write-Host "Creating necessary directories..."
New-Item -ItemType Directory -Force -Path "$IISPath\logs"
New-Item -ItemType Directory -Force -Path "$IISPath\uploads\contracts"
New-Item -ItemType Directory -Force -Path "$IISPath\uploads\chatFiles"

# Set IIS permissions
Write-Host "Setting IIS permissions..."
$Acl = Get-Acl $IISPath
$Rule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$Acl.SetAccessRule($Rule)
Set-Acl $IISPath $Acl

# Database migrations
Write-Host "Running database migrations..."
flask db upgrade

# Restart IIS
Write-Host "Restarting IIS..."
iisreset

Write-Host "Deployment completed successfully!" 