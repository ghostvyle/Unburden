#!/usr/bin/env bash
#
# Unburden v.1 - Cybersecurity AI Assistant
# Startup script
#

set -e

# Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
RED='\033[0;31m'
NC='\033[0m'

# Paths
PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
VENV_PATH="$PROJECT_ROOT/.venv"

# Cleanup function for Ctrl+C
cleanup() {
    echo ""
    echo -e "${RED}>> Shutting down Unburden...${NC}"

    # Kill msfrpcd processes
    if pgrep -f "msfrpcd" > /dev/null 2>&1; then
        echo -e "${GRAY}   • Stopping Metasploit RPC daemon...${NC}"
        sudo pkill -f "msfrpcd" 2>/dev/null || true
    fi

    # Kill metasploit.py processes
    if pgrep -f "metasploit.py" > /dev/null 2>&1; then
        echo -e "${GRAY}   • Stopping Metasploit MCP server...${NC}"
        pkill -f "metasploit.py" 2>/dev/null || true
    fi

    echo -e "${GRAY}   • Cleanup complete${NC}"
    exit 0
}

# Trap Ctrl+C and call cleanup
trap cleanup SIGINT SIGTERM

# Clear screen
clear

# Banner
echo -e "${GREEN}"
echo -e " █    ██  ███▄    █  ▄▄▄▄    █    ██  ██▀███  ▓█████▄ ▓█████  ███▄    █ "
echo -e " ██  ▓██▒ ██ ▀█   █ ▓█████▄  ██  ▓██▒▓██ ▒ ██▒▒██▀ ██▌▓█   ▀  ██ ▀█   █ "
echo -e "▓██  ▒██░▓██  ▀█ ██▒▒██▒ ▄██▓██  ▒██░▓██ ░▄█ ▒░██   █▌▒███   ▓██  ▀█ ██▒"
echo -e "▓▓█  ░██░▓██▒  ▐▌██▒▒██░█▀  ▓▓█  ░██░▒██▀▀█▄  ░▓█▄   ▌▒▓█  ▄ ▓██▒  ▐▌██▒"
echo -e "▒▒█████▓ ▒██░   ▓██░░▓█  ▀█▓▒▒█████▓ ░██▓ ▒██▒░▒████▓ ░▒████▒▒██░   ▓██░"
echo -e "░▒▓▒ ▒ ▒ ░ ▒░   ▒ ▒ ░▒▓███▀▒░▒▓▒ ▒ ▒ ░ ▒▓ ░▒▓░ ▒▒▓  ▒ ░░ ▒░ ░░ ▒░   ▒ ▒ "
echo -e "░░▒░ ░ ░ ░ ░░   ░ ▒░▒░▒   ░ ░░▒░ ░ ░   ░▒ ░ ▒░ ░ ▒  ▒  ░ ░  ░░ ░░   ░ ▒░"
echo -e " ░░░ ░ ░    ░   ░ ░  ░    ░  ░░░ ░ ░   ░░   ░  ░ ░  ░    ░      ░   ░ ░ "
echo -e "   ░              ░  ░         ░        ░        ░       ░  ░         ░ "
echo -e "                          ░                    ░                        "
echo -e "${NC}"
echo -e "${GRAY}  Cybersecurity AI Assistant • Pentesting • OSINT • Automation${NC}"
echo ""

# Initialize services
echo -e "${CYAN}>> Initializing services...${NC}"

# Activate venv
source "$VENV_PATH/bin/activate" 2>/dev/null
echo -e "${GRAY}   • Python environment: active${NC}"

# Start msfrpcd
sudo msfrpcd -U msf -P 123456 -a 127.0.0.1 -p 55553 -S -f > /dev/null 2>&1 &
sleep 2
if pgrep -f "msfrpcd" > /dev/null; then
    echo -e "${GRAY}   • Metasploit RPC daemon: running (PID: $(pgrep -f msfrpcd | head -1))${NC}"
fi

echo ""
echo -e "${CYAN}>> Access points:${NC}"
echo -e "${GRAY}   • Frontend: http://localhost:7777/app${NC}"
echo -e "${GRAY}   • API Docs: http://localhost:7777/docs${NC}"
echo -e "${GRAY}   • Health:   http://localhost:7777/health${NC}"
echo ""
echo -e "${GRAY}   [Press Ctrl+C to terminate]${NC}"
echo ""

# Start Unburden
sudo "$VENV_PATH/bin/python3" src/Unburden.py
