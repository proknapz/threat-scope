@echo off
REM Threat-Scope Startup Script for Windows

echo 🚀 Starting Threat-Scope PHP Vulnerability Scanner
echo ==================================================

REM Check if Docker is installed
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker is not installed. Please install Docker Desktop first.
    pause
    exit /b 1
)

docker-compose --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker Compose is not installed. Please install Docker Compose first.
    pause
    exit /b 1
)

REM Stop any existing containers
echo 🛑 Stopping existing containers...
docker-compose down

REM Start the services
echo 🐳 Starting Docker services...
docker-compose up -d

REM Wait for services to be ready
echo ⏳ Waiting for services to start...
timeout /t 10 /nobreak >nul

REM Check if services are running
echo 🔍 Checking service status...
docker-compose ps

REM Run tests
echo 🧪 Running setup tests...
python test_setup.py
set TEST_RESULT=%errorlevel%

echo.
echo ✅ Threat-Scope is now running!
echo.
echo 📋 Access URLs:
echo   • Main Scanner: http://127.0.0.1:5000 (or http://localhost:5000)
echo   • Database Management: http://127.0.0.1:5000/database
echo   • phpMyAdmin: http://localhost:8080
echo.
echo 🔧 MySQL Credentials:
echo   • Host: localhost:3306
echo   • Database: threat_scope
echo   • Username: threat_user
echo   • Password: threat_password
echo   • Root Password: rootpassword
echo.
echo 💡 To stop the services, run: docker-compose down
echo.

if %TEST_RESULT% neq 0 (
    echo ⚠️  Note: Some tests failed, but services are running. Check logs above for details.
)

pause
