@echo off

:: Remove Python cache files
del /s /q *.pyc
for /d /r . %%d in (__pycache__) do @if exist "%%d" rd /s /q "%%d"

:: Remove logs
del /s /q logs\*
type nul > logs\.gitkeep

:: Remove uploads
del /s /q uploads\*
mkdir uploads\contracts uploads\chatFiles
type nul > uploads\contracts\.gitkeep
type nul > uploads\chatFiles\.gitkeep

:: Remove database
if exist app.db del app.db

:: Remove environment files
if exist .env del .env

:: Remove IDE files
if exist .vscode rmdir /s /q .vscode
if exist .idea rmdir /s /q .idea

:: Remove test files
if exist tests rmdir /s /q tests
if exist pytest.ini del pytest.ini
if exist .pytest_cache rmdir /s /q .pytest_cache
if exist htmlcov rmdir /s /q htmlcov
if exist .coverage del .coverage

:: Remove any temporary files
del /q *.log
del /q *.tmp

echo Cleanup completed successfully!
pause 