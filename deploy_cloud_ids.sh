#!/usr/bin/env bash
# ==============================================================================
# Google Cloud IDS — End-to-End Deployment & Attack Simulation Orchestrator
# Workflow:
#   1. IDS Endpoint     -> Create managed IDS endpoint collector in target VPC
#   2. Target VMs       -> Deploy client VM (attacker) and server VM (target)
#   3. Packet Mirroring -> Configure Packet Mirroring policy to IDS Endpoint
#   4. Attack Sim       -> Run safe curl exploit/malware simulations from client VM
#   5. Verification     -> Check threat logs in Cloud Logging & Cloud Console
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
CONFIG_FILE="${SCRIPT_DIR}/config.yaml"

CLI_PROJECT_ID=""
STEP="all"
DRY_RUN=false
CLEANUP=false

usage() {
    cat <<EOF
Usage: ./deploy_cloud_ids.sh [OPTIONS]

Options:
  --project <PROJECT_ID>   GCP Project ID (overrides project_id in config.yaml)
  --step <1|2|3|4|5|all>   Run a specific deployment/test step or all (default: all)
  --dry-run                Print gcloud commands without executing them
  --cleanup                Tear down Packet Mirroring, VMs, IDS Endpoint, and VPC
  -h, --help               Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project)
            CLI_PROJECT_ID="$2"
            shift 2
            ;;
        --step)
            STEP="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --cleanup)
            CLEANUP=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown argument: $1${NC}"
            usage
            exit 1
            ;;
    esac
done

# Safe YAML reader using yaml.safe_load()
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
REGION="$(cfg_get "region" "us-central1")"
ZONE="$(cfg_get "zone" "us-central1-a")"

VPC_NAME="$(cfg_get "network.vpc_name" "cloud-ids-vpc")"
SUBNET_NAME="$(cfg_get "network.subnet_name" "cloud-ids-subnet")"
SUBNET_CIDR="$(cfg_get "network.subnet_cidr" "192.168.10.0/24")"
PSA_RANGE_NAME="$(cfg_get "network.psa_range_name" "google-managed-services-cloud-ids")"
PSA_PREFIX_LEN="$(cfg_get "network.psa_prefix_length" "24")"
ROUTER_NAME="$(cfg_get "network.router_name" "cloud-ids-nat-router")"
NAT_NAME="$(cfg_get "network.nat_name" "cloud-ids-nat-gw")"

IDS_ENDPOINT_NAME="$(cfg_get "ids_endpoint.name" "cloud-ids-endpoint-01")"
IDS_SEVERITY="$(cfg_get "ids_endpoint.severity" "INFORMATIONAL")"
ENABLE_TRAFFIC_LOGS="$(cfg_get "ids_endpoint.enable_traffic_logs" "true")"

SERVER_VM="$(cfg_get "target_vms.server_vm.name" "ids-target-server")"
SERVER_MACHINE_TYPE="$(cfg_get "target_vms.server_vm.machine_type" "e2-medium")"
SERVER_IP="$(cfg_get "target_vms.server_vm.internal_ip" "192.168.10.10")"

CLIENT_VM="$(cfg_get "target_vms.client_vm.name" "ids-attacker-client")"
CLIENT_MACHINE_TYPE="$(cfg_get "target_vms.client_vm.machine_type" "e2-medium")"
CLIENT_IP="$(cfg_get "target_vms.client_vm.internal_ip" "192.168.10.20")"

MIRROR_POLICY_NAME="$(cfg_get "packet_mirroring.policy_name" "cloud-ids-packet-mirroring")"
MIRROR_DIRECTION="$(cfg_get "packet_mirroring.direction" "BOTH")"

# Input validation against strict allow-lists (mandatory-secure-web-skills)
validate_identifier() {
    local val="$1"
    local label="$2"
    if [[ ! "$val" =~ ^[a-zA-Z0-9_-]{2,63}$ ]]; then
        echo -e "${RED}Error: Invalid ${label} '${val}'.${NC}"
        exit 1
    fi
}

if [[ "$PROJECT_ID" == "YOUR_PROJECT_ID" || -z "$PROJECT_ID" ]]; then
    if [[ "$DRY_RUN" == "false" ]]; then
        echo -e "${RED}Error: project_id is still set to placeholder 'YOUR_PROJECT_ID'.${NC}"
        echo -e "Please fill in ${CYAN}project_id${NC} in ${GREEN}config.yaml${NC} or pass ${GREEN}--project <PROJECT_ID>${NC}."
        exit 1
    fi
else
    validate_identifier "$PROJECT_ID" "PROJECT_ID"
fi

validate_identifier "$REGION" "REGION"
validate_identifier "$ZONE" "ZONE"
validate_identifier "$VPC_NAME" "VPC_NAME"
validate_identifier "$SUBNET_NAME" "SUBNET_NAME"
validate_identifier "$IDS_ENDPOINT_NAME" "IDS_ENDPOINT_NAME"
validate_identifier "$SERVER_VM" "SERVER_VM"
validate_identifier "$CLIENT_VM" "CLIENT_VM"
validate_identifier "$MIRROR_POLICY_NAME" "MIRROR_POLICY_NAME"

run_gcloud() {
    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "  ${YELLOW}[DRY-RUN]${NC} gcloud $*"
    else
        echo -e "  ${CYAN}▶${NC} gcloud $*"
        gcloud "$@"
    fi
}

echo -e "${BLUE}====================================================================${NC}"
echo -e "${BLUE}${BOLD}   Google Cloud IDS — Deployment & Attack Simulation Pipeline       ${NC}"
echo -e "${BLUE}====================================================================${NC}"
echo -e "  ${CYAN}Project ID:${NC}         ${BOLD}${PROJECT_ID}${NC}"
echo -e "  ${CYAN}Region / Zone:${NC}      ${REGION} / ${ZONE}"
echo -e "  ${CYAN}VPC / Subnet:${NC}       ${VPC_NAME} / ${SUBNET_NAME} (${SUBNET_CIDR})"
echo -e "  ${CYAN}IDS Endpoint:${NC}       ${IDS_ENDPOINT_NAME} (Severity: ${IDS_SEVERITY})"
echo -e "  ${CYAN}Target VMs:${NC}         ${CLIENT_VM} (${CLIENT_IP}) ──> ${SERVER_VM} (${SERVER_IP})"
echo -e "  ${CYAN}Packet Mirroring:${NC}   ${MIRROR_POLICY_NAME} (Direction: ${MIRROR_DIRECTION})"
echo -e "${BLUE}====================================================================${NC}"

# ==============================================================================
# Cleanup Mode (--cleanup)
# ==============================================================================
if [[ "$CLEANUP" == "true" ]]; then
    echo -e "\n${YELLOW}Tearing down Cloud IDS lab resources in project ${PROJECT_ID}...${NC}"
    run_gcloud compute packet-mirrorings delete "${MIRROR_POLICY_NAME}" --region="${REGION}" --project="${PROJECT_ID}" --quiet || true
    run_gcloud compute instances delete "${CLIENT_VM}" "${SERVER_VM}" --zone="${ZONE}" --project="${PROJECT_ID}" --quiet || true
    run_gcloud ids endpoints delete "${IDS_ENDPOINT_NAME}" --zone="${ZONE}" --project="${PROJECT_ID}" --quiet || true
    echo -e "${GREEN}✓ Cleanup commands completed.${NC}"
    exit 0
fi

# ==============================================================================
# STEP 1: Create Managed Cloud IDS Endpoint in Target VPC Network
# ==============================================================================
if [[ "$STEP" == "all" || "$STEP" == "1" ]]; then
    echo -e "\n${YELLOW}${BOLD}[Step 1/5] Provisioning VPC, Private Services Access & Cloud IDS Endpoint...${NC}"

    # 1.1 Enable Required APIs
    run_gcloud services enable \
        compute.googleapis.com \
        servicenetworking.googleapis.com \
        ids.googleapis.com \
        logging.googleapis.com \
        iap.googleapis.com \
        --project="${PROJECT_ID}"

    # 1.2 Create VPC & Subnet (if not already present)
    if [[ "$DRY_RUN" == "true" ]] || ! gcloud compute networks describe "${VPC_NAME}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
        run_gcloud compute networks create "${VPC_NAME}" \
            --subnet-mode=custom \
            --project="${PROJECT_ID}"
    fi

    if [[ "$DRY_RUN" == "true" ]] || ! gcloud compute networks subnets describe "${SUBNET_NAME}" --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
        run_gcloud compute networks subnets create "${SUBNET_NAME}" \
            --network="${VPC_NAME}" \
            --region="${REGION}" \
            --range="${SUBNET_CIDR}" \
            --enable-private-ip-google-access \
            --project="${PROJECT_ID}"
    fi

    # 1.3 Configure Private Services Access (PSA) for Cloud IDS
    if [[ "$DRY_RUN" == "true" ]] || ! gcloud compute addresses describe "${PSA_RANGE_NAME}" --global --project="${PROJECT_ID}" >/dev/null 2>&1; then
        run_gcloud compute addresses create "${PSA_RANGE_NAME}" \
            --global \
            --purpose=VPC_PEERING \
            --prefix-length="${PSA_PREFIX_LEN}" \
            --network="${VPC_NAME}" \
            --project="${PROJECT_ID}"
    fi

    run_gcloud services vpc-peerings connect \
        --service=servicenetworking.googleapis.com \
        --ranges="${PSA_RANGE_NAME}" \
        --network="${VPC_NAME}" \
        --project="${PROJECT_ID}" || true

    # 1.4 Create Managed Cloud IDS Endpoint
    TRAFFIC_LOG_FLAG="--enable-traffic-logs"
    if [[ "${ENABLE_TRAFFIC_LOGS,,}" != "true" ]]; then
        TRAFFIC_LOG_FLAG="--no-enable-traffic-logs"
    fi

    if [[ "$DRY_RUN" == "true" ]] || ! gcloud ids endpoints describe "${IDS_ENDPOINT_NAME}" --zone="${ZONE}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
        run_gcloud ids endpoints create "${IDS_ENDPOINT_NAME}" \
            --network="${VPC_NAME}" \
            --zone="${ZONE}" \
            --severity="${IDS_SEVERITY}" \
            "${TRAFFIC_LOG_FLAG}" \
            --async \
            --project="${PROJECT_ID}"
    fi
fi

# ==============================================================================
# STEP 2: Deploy Target VMs — Client VM (Attacker) & Server VM (Target)
# ==============================================================================
if [[ "$STEP" == "all" || "$STEP" == "2" ]]; then
    echo -e "\n${YELLOW}${BOLD}[Step 2/5] Deploying Cloud NAT, Firewall Rules & Target VMs...${NC}"

    # 2.1 Cloud Router & Cloud NAT (so private VMs have outbound package access without public IPs)
    if [[ "$DRY_RUN" == "true" ]] || ! gcloud compute routers describe "${ROUTER_NAME}" --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
        run_gcloud compute routers create "${ROUTER_NAME}" \
            --network="${VPC_NAME}" \
            --region="${REGION}" \
            --project="${PROJECT_ID}"
    fi

    if [[ "$DRY_RUN" == "true" ]] || ! gcloud compute routers nats describe "${NAT_NAME}" --router="${ROUTER_NAME}" --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
        run_gcloud compute routers nats create "${NAT_NAME}" \
            --router="${ROUTER_NAME}" \
            --region="${REGION}" \
            --auto-allocate-nat-external-ips \
            --nat-all-subnet-ip-ranges \
            --project="${PROJECT_ID}"
    fi

    # 2.2 Firewall Rules (IAP SSH + Internal HTTP/ICMP)
    if [[ "$DRY_RUN" == "true" ]] || ! gcloud compute firewall-rules describe "${VPC_NAME}-allow-iap-ssh" --project="${PROJECT_ID}" >/dev/null 2>&1; then
        run_gcloud compute firewall-rules create "${VPC_NAME}-allow-iap-ssh" \
            --network="${VPC_NAME}" \
            --direction=INGRESS \
            --action=ALLOW \
            --rules=tcp:22 \
            --source-ranges=35.235.240.0/20 \
            --target-tags=ids-monitored \
            --project="${PROJECT_ID}"
    fi

    if [[ "$DRY_RUN" == "true" ]] || ! gcloud compute firewall-rules describe "${VPC_NAME}-allow-internal-http-icmp" --project="${PROJECT_ID}" >/dev/null 2>&1; then
        run_gcloud compute firewall-rules create "${VPC_NAME}-allow-internal-http-icmp" \
            --network="${VPC_NAME}" \
            --direction=INGRESS \
            --action=ALLOW \
            --rules=tcp:80,tcp:8080,icmp \
            --source-ranges="${SUBNET_CIDR}" \
            --target-tags=ids-monitored \
            --project="${PROJECT_ID}"
    fi

    # 2.3 Deploy Target Server VM (Apache2 + EICAR test payload)
    SERVER_STARTUP='#! /bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y apache2 curl
systemctl enable apache2
systemctl start apache2
mkdir -p /var/www/html/cgi-bin
echo "<html><body><h1>Mock WebLogin CGI</h1></body></html>" > /var/www/html/weblogin.cgi
echo "<html><body><h1>Mock CGI Endpoint</h1></body></html>" > /var/www/html/cgi-bin/test-critical
printf "X5O!P%%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*" > /var/www/html/eicar.file
chmod 644 /var/www/html/eicar.file /var/www/html/weblogin.cgi /var/www/html/cgi-bin/test-critical'

    if [[ "$DRY_RUN" == "true" ]] || ! gcloud compute instances describe "${SERVER_VM}" --zone="${ZONE}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
        run_gcloud compute instances create "${SERVER_VM}" \
            --zone="${ZONE}" \
            --machine-type="${SERVER_MACHINE_TYPE}" \
            --subnet="${SUBNET_NAME}" \
            --private-network-ip="${SERVER_IP}" \
            --no-address \
            --image-family=debian-12 \
            --image-project=debian-cloud \
            --shielded-secure-boot \
            --shielded-vtpm \
            --shielded-integrity-monitoring \
            --tags=ids-monitored,ids-target-server \
            --metadata="enable-oslogin=TRUE,startup-script=${SERVER_STARTUP}" \
            --project="${PROJECT_ID}"
    fi

    # 2.4 Deploy Attacker Client VM
    CLIENT_STARTUP='#! /bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl dnsutils'

    if [[ "$DRY_RUN" == "true" ]] || ! gcloud compute instances describe "${CLIENT_VM}" --zone="${ZONE}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
        run_gcloud compute instances create "${CLIENT_VM}" \
            --zone="${ZONE}" \
            --machine-type="${CLIENT_MACHINE_TYPE}" \
            --subnet="${SUBNET_NAME}" \
            --private-network-ip="${CLIENT_IP}" \
            --no-address \
            --image-family=debian-12 \
            --image-project=debian-cloud \
            --shielded-secure-boot \
            --shielded-vtpm \
            --shielded-integrity-monitoring \
            --tags=ids-monitored,ids-attacker-client \
            --metadata="enable-oslogin=TRUE,startup-script=${CLIENT_STARTUP}" \
            --project="${PROJECT_ID}"
    fi
fi

# ==============================================================================
# STEP 3: Configure Packet Mirroring Policy to Copy Traffic to IDS Endpoint
# ==============================================================================
if [[ "$STEP" == "all" || "$STEP" == "3" ]]; then
    echo -e "\n${YELLOW}${BOLD}[Step 3/5] Configuring Packet Mirroring Policy to Cloud IDS Endpoint...${NC}"

    ENDPOINT_FORWARDING_RULE=""
    if [[ "$DRY_RUN" == "true" ]]; then
        ENDPOINT_FORWARDING_RULE="https://www.googleapis.com/compute/v1/projects/${PROJECT_ID}/regions/${REGION}/forwardingRules/ids-forwarding-rule-placeholder"
    else
        echo -e "  ${CYAN}Checking Cloud IDS Endpoint (${IDS_ENDPOINT_NAME}) readiness...${NC}"
        while true; do
            STATE=$(gcloud ids endpoints describe "${IDS_ENDPOINT_NAME}" \
                --zone="${ZONE}" \
                --project="${PROJECT_ID}" \
                --format="value(state)" 2>/dev/null || echo "CREATING")
            if [[ "$STATE" == "READY" ]]; then
                ENDPOINT_FORWARDING_RULE=$(gcloud ids endpoints describe "${IDS_ENDPOINT_NAME}" \
                    --zone="${ZONE}" \
                    --project="${PROJECT_ID}" \
                    --format="value(endpointForwardingRule)")
                echo -e "  ${GREEN}✓ Cloud IDS Endpoint is READY!${NC}"
                echo -e "  ${GREEN}✓ Collector ILB Forwarding Rule:${NC} ${ENDPOINT_FORWARDING_RULE}"
                break
            fi
            echo -e "  ${YELLOW}Endpoint state is '${STATE}'. Waiting 30s for Cloud IDS Endpoint provisioning...${NC}"
            sleep 30
        done
    fi

    if [[ "$DRY_RUN" == "true" ]] || ! gcloud compute packet-mirrorings describe "${MIRROR_POLICY_NAME}" --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
        run_gcloud compute packet-mirrorings create "${MIRROR_POLICY_NAME}" \
            --network="${VPC_NAME}" \
            --region="${REGION}" \
            --collector-ilb="${ENDPOINT_FORWARDING_RULE}" \
            --mirrored-subnets="${SUBNET_NAME}" \
            --mirrored-instances="zones/${ZONE}/instances/${SERVER_VM},zones/${ZONE}/instances/${CLIENT_VM}" \
            --enable \
            --project="${PROJECT_ID}"
    fi
fi

# ==============================================================================
# STEP 4: Attack Simulation — Run Safe Attack Scripts from Client VM
# ==============================================================================
if [[ "$STEP" == "all" || "$STEP" == "4" ]]; then
    echo -e "\n${YELLOW}${BOLD}[Step 4/5] Running Safe Attack Traffic Simulation...${NC}"
    if [[ "$DRY_RUN" == "true" ]]; then
        "${SCRIPT_DIR}/scripts/simulate_attacks.sh" --project "${PROJECT_ID}" --dry-run
    else
        "${SCRIPT_DIR}/scripts/simulate_attacks.sh" --project "${PROJECT_ID}"
    fi
fi

# ==============================================================================
# STEP 5: Verification — Check Threat Logs in Cloud Logging / Cloud Console
# ==============================================================================
if [[ "$STEP" == "all" || "$STEP" == "5" ]]; then
    echo -e "\n${YELLOW}${BOLD}[Step 5/5] Verifying Cloud IDS Threat Alerts in Cloud Logging...${NC}"
    if [[ "$DRY_RUN" == "true" ]]; then
        "${SCRIPT_DIR}/scripts/verify_alerts.sh" --project "${PROJECT_ID}" --dry-run
    else
        "${SCRIPT_DIR}/scripts/verify_alerts.sh" --project "${PROJECT_ID}" --wait
    fi
fi
