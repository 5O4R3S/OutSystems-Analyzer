#!/bin/bash

# Terminal Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Set working directory to the script's location
cd "$(dirname "$0")"

PORT=${PORT:-5000}

echo -e "${GREEN}------------------------------------------${NC}"
echo -e "${GREEN}     Starting OutSystems Analyzer...      ${NC}"
echo -e "${GREEN}------------------------------------------${NC}"

# Check if port is already in use
PID=$(lsof -t -i:$PORT 2>/dev/null)

if [ -z "$PID" ]; then
    echo -e "[*] Port $PORT is free."
else
    echo -e "${YELLOW}[!] Port $PORT is in use by PID: $PID. Killing process...${NC}"
    kill -15 $PID 2>/dev/null
    sleep 2
    # Force kill if still running
    if kill -0 $PID 2>/dev/null; then
        kill -9 $PID 2>/dev/null
    fi
    echo -e "${GREEN}[+] Port $PORT is now available.${NC}"
fi

# Verify if Virtual Environment exists
if [ ! -d "OSANALYZER" ]; then
    echo -e "${RED}Error: Virtual environment 'OSANALYZER' not found.${NC}"
    echo "Please run ./setup.sh first."
    exit 1
fi

# Activate environment and launch
source OSANALYZER/bin/activate
echo -e "[*] Server starting at http://127.0.0.1:$PORT"
python3 main.py