#!/bin/bash

echo "🚀 Starting SSL Checker Pro..."
echo "📦 Building and starting containers..."

# Build and start the application
docker-compose up --build -d

echo "✅ SSL Checker Pro is starting up!"
echo "🌐 Open your browser and go to: http://localhost:3000"
echo ""
echo "📋 Useful commands:"
echo "  View logs: docker-compose logs"
echo "  Stop app:  docker-compose down"
echo "  Restart:   docker-compose restart"
echo ""
echo "🛡️ SSL Checker Pro - Free • Secure • Private" 