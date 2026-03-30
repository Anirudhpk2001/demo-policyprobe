#!/bin/bash
#
# PolicyProbe Backend Environment Setup
#
# This script creates a Python virtual environment and installs dependencies.
# Run from the project root: ./scripts/setup_env.sh
#
# Override Python version: PYTHON_PATH=/path/to/python ./scripts/setup_env.sh
#

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "=========================================="
echo "  Setting up Python Environment"
echo "=========================================="
echo ""

# Find suitable Python interpreter (3.10+)
source "$PROJECT_ROOT/scripts/python_helper.sh"
echo ""

cd "$PROJECT_ROOT/backend"

# Create virtual environment if it doesn't exist
if [ -d ".venv" ]; then
    echo "✓ Virtual environment already exists"
    echo "  To recreate, remove .venv first: rm -rf backend/.venv"
    echo ""
else
    echo "Creating Python virtual environment..."
    "$PYTHON_CMD" -m venv .venv
    echo "✓ Virtual environment created"
    echo ""
fi

# Activate virtual environment
echo "Activating virtual environment..."
source .venv/bin/activate
echo "✓ Virtual environment activated"
echo ""

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip
echo "✓ pip upgraded"
echo ""

# Install requirements
echo "Installing Python dependencies..."
pip install -r requirements.txt
echo "✓ Dependencies installed"
echo ""

# Install frontend dependencies
echo "Installing frontend dependencies..."
cd "$PROJECT_ROOT/frontend"
if [ ! -d "node_modules" ] || [ ! -f "node_modules/.bin/next" ]; then
    echo "Installing npm packages..."
    npm install
    echo "✓ Frontend dependencies installed"
else
    echo "✓ Frontend dependencies already installed"
fi
echo ""

echo "=========================================="
echo "  Setup Complete!"
echo "=========================================="
echo ""
echo "  Virtual environment: backend/.venv"
echo "  To activate manually: source backend/.venv/bin/activate"
echo ""
echo "=========================================="
