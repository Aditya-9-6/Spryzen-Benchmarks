#!/bin/bash
# ==============================================================================
# Spryzen Enterprise WAF - 1-Line Universal Installer & Deployment Script
# Usage: curl -fsSL https://raw.githubusercontent.com/Aditya-9-6/spryzen/main/install.sh | bash
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${CYAN}${BOLD}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════════════╗
║       SPRYZEN+ ENTERPRISE REVERSE PROXY & API SECURITY GATEWAY       ║
║       Architecture: AVX2 SIMD + Zero-Alloc Bitmasks + L1 Cache        ║
║       Production Installer & Cloud-Native Deployment Tool            ║
╚══════════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# 1. Check Container Engine
CONTAINER_RUNTIME=""
if command -v docker &> /dev/null; then
    CONTAINER_RUNTIME="docker"
elif command -v podman &> /dev/null; then
    CONTAINER_RUNTIME="podman"
else
    echo -e "${RED}[ERROR] Neither Docker nor Podman was detected on this machine.${NC}"
    echo -e "Please install Docker (https://docs.docker.com/engine/install/) and rerun this script."
    exit 1
fi

echo -e "${GREEN}✓ Container runtime detected:${NC} ${CONTAINER_RUNTIME}"

# 2. Check Architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        IMAGE_ARCH="amd64"
        ;;
    aarch64|arm64)
        IMAGE_ARCH="arm64"
        ;;
    *)
        echo -e "${YELLOW}Warning: Unknown architecture $ARCH. Defaulting to standard pull.${NC}"
        ;;
esac
echo -e "${GREEN}✓ System Architecture:${NC} ${ARCH}"

# 3. Pull Spryzen Container Image from GHCR
IMAGE="ghcr.io/aditya-9-6/spryzen:latest"
echo -e "\n${BLUE}==> Pulling official enterprise container image: ${IMAGE}...${NC}"
$CONTAINER_RUNTIME pull $IMAGE

# 4. Generate spryzen.toml if missing
CONFIG_FILE="spryzen.toml"
if [ ! -f "$CONFIG_FILE" ]; then
    echo -e "${BLUE}==> Creating default enterprise configuration (${CONFIG_FILE})...${NC}"
    cat << 'CONFIG_EOF' > spryzen.toml
[server]
listen = "0.0.0.0:8080"
mode = "simulate" # Change to "block" when ready to enforce
timeout_ms = 10000
max_body_bytes = 10485760

[rate_limit]
enabled = true
requests_per_second = 5000
burst = 10000

[allowlist]
paths = [
  "/health",
  "/metrics",
  "/_spryzen/*"
]
ips = []

[logging]
format = "json"
mask_headers = [
  "authorization",
  "cookie",
  "x-api-key",
  "proxy-authorization"
]
CONFIG_EOF
    echo -e "${GREEN}✓ Created ${CONFIG_FILE} in current directory.${NC}"
fi

# 5. Summary & Next Steps
echo -e "\n${GREEN}${BOLD}======================================================================${NC}"
echo -e "${GREEN}${BOLD}✓ SPRYZEN ENTERPRISE WAF IS READY TO DEPLOY!${NC}"
echo -e "${GREEN}${BOLD}======================================================================${NC}"

echo -e "\n${BOLD}Quickstart 1: Drop in front of an existing backend (Simulate Mode - 0% Risk):${NC}"
echo -e "  ${CYAN}$CONTAINER_RUNTIME run -d --name spryzen -p 80:8080 \\"
echo -e "    -e UPSTREAM_URL=\"http://your-backend:80\" \\"
echo -e "    -e SPRYZEN_MODE=\"simulate\" \\"
echo -e "    ${IMAGE}${NC}"

echo -e "\n${BOLD}Quickstart 2: Run in Active Blocking Mode (100% OWASP CRS Protection):${NC}"
echo -e "  ${CYAN}$CONTAINER_RUNTIME run -d --name spryzen -p 80:8080 \\"
echo -e "    -e UPSTREAM_URL=\"http://your-backend:80\" \\"
echo -e "    -e SPRYZEN_MODE=\"block\" \\"
echo -e "    ${IMAGE}${NC}"

echo -e "\n${BOLD}Quickstart 3: Kubernetes Helm Deployment:${NC}"
echo -e "  ${CYAN}helm upgrade --install spryzen ./charts/spryzen \\"
echo -e "    --set spryzen.upstreamUrl=\"http://my-service:80\" \\"
echo -e "    --set spryzen.mode=\"simulate\"${NC}"

echo -e "\n${BOLD}Health & Verification:${NC}"
echo -e "  ${CYAN}curl -i http://localhost:8080/health${NC}"
echo -e "  ${CYAN}curl -i http://localhost:8080/metrics${NC}"
echo -e "\nFor full enterprise evaluation runbook, see ${BOLD}EVALUATION_GUIDE.md${NC}.\n"
