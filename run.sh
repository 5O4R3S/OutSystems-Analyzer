#!/bin/bash

# Terminal Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

PORT=5000

echo -e "${GREEN}------------------------------------------${NC}"
echo -e "${GREEN}     Starting OutSystems Analyzer...      ${NC}"
echo -e "${GREEN}------------------------------------------${NC}"

# Check if port is already in use
# Redirecting stderr to /dev/null to keep it clean if lsof is not installed
PID=$(lsof -t -i:$PORT 2>/dev/null)

if [ -z "$PID" ]; then
    echo -e "[*] Port $PORT is free."
else
    echo -e "${YELLOW}[!] Port $PORT is in use by PID: $PID. Killing process...${NC}"
    kill -9 $PID
    sleep 1 
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