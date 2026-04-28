#!/bin/bash
# Quick startup verification script

echo "═══════════════════════════════════════════════════════════"
echo "Minerva MCP Pentesting Framework - Docker Compose Startup Check"
echo "═══════════════════════════════════════════════════════════"
echo ""

# Check if docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker daemon is not running"
    exit 1
fi
echo "✓ Docker is running"

# Check docker-compose
if ! command -v docker-compose &> /dev/null && ! docker compose version > /dev/null 2>&1; then
    echo "❌ docker-compose is not installed"
    exit 1
fi
echo "✓ docker-compose is available"

# Check .env file
if [ ! -f .env ]; then
    echo "⚠️  .env file not found - using defaults"
else
    echo "✓ .env file found"
fi

echo ""
echo "Starting Minerva services with docker-compose..."
echo ""
echo "Services to start:"
echo "  - PostgreSQL (port 5432)"
echo "  - Redis (port 6379)"
echo "  - Backend API (port 5000)"
echo "  - Celery Worker"
echo "  - Celery Beat"
echo "  - Frontend (port 80)"
echo ""

# Run docker-compose
docker-compose up --build

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "If you see errors above, check:"
echo "  1. Docker daemon is running"
echo "  2. Ports 80, 5000, 5432, 6379 are available"
echo "  3. .env file has correct database credentials"
echo "═══════════════════════════════════════════════════════════"
