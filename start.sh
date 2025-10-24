#!/bin/bash

# Threat-Scope Startup Script

echo "🚀 Starting Threat-Scope PHP Vulnerability Scanner"
echo "=================================================="

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Stop any existing containers
echo "🛑 Stopping existing containers..."
docker-compose down

# Start the services
echo "🐳 Starting Docker services..."
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 10

# Check if services are running
echo "🔍 Checking service status..."
docker-compose ps

# Run tests
echo "🧪 Running setup tests..."
python3 test_setup.py

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Threat-Scope is now running!"
    echo ""
    echo "📋 Access URLs:"
    echo "  • Main Scanner: http://localhost:5000"
    echo "  • Database Management: http://localhost:5000/database"
    echo "  • phpMyAdmin: http://localhost:8080"
    echo ""
    echo "🔧 MySQL Credentials:"
    echo "  • Host: localhost:3306"
    echo "  • Database: threat_scope"
    echo "  • Username: threat_user"
    echo "  • Password: threat_password"
    echo "  • Root Password: rootpassword"
    echo ""
    echo "To stop the services, run: docker-compose down"
else
    echo "❌ Setup tests failed. Please check the logs above."
    exit 1
fi
