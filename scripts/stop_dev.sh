#!/bin/bash
#
# PolicyProbe Development Server Stop Script
#
# This script stops both the frontend and backend servers.
# Run from anywhere: ./scripts/stop_dev.sh
#

echo "=========================================="
echo "  Stopping PolicyProbe Servers"
echo "=========================================="
echo ""

# Stop backend on port 5500
if lsof -i :5500 -t > /dev/null 2>&1; then
    lsof -i :5500 -t | xargs kill -9 2>/dev/null
    echo "✓ Backend stopped (port 5500)"
else
    echo "- Backend was not running"
fi

# Stop frontend on port 5001
if lsof -i :5001 -t > /dev/null 2>&1; then
    lsof -i :5001 -t | xargs kill -9 2>/dev/null
    echo "✓ Frontend stopped (port 5001)"
else
    echo "- Frontend was not running"
fi

echo ""
echo "=========================================="
echo "  All servers stopped"
echo "=========================================="
