#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "------------------------------------------"
echo "  OutSystems Analyzer - Setup Assistant   "
echo "------------------------------------------"

# 1. Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 not found. Please install it before continuing."
    exit 1
fi

# 2. Create Virtual Environment if it doesn't exist
if [ ! -d "OSANALYZER" ]; then
    echo "[*] Creating a Python virtual environment (OSANALYZER)..."
    python3 -m venv OSANALYZER
fi

# 3. Activate Environment and Install Dependencies
echo "[*] Activating environment and updating pip..."
source OSANALYZER/bin/activate
pip install --upgrade pip

if [ -f "requirements.txt" ]; then
    echo "[*] Installing dependencies from requirements.txt..."
    pip install -r requirements.txt
else
    echo "Warning: requirements.txt not found. Skipping dependency installation."
fi

# 4. Playwright Setup
echo "[*] Installing Playwright browsers (Chromium)..."
python3 -m playwright install chromium

echo "------------------------------------------"
echo "Configuration completed successfully!"
echo "To run the application, simply use:"
echo "  ./run.sh"
echo "------------------------------------------"