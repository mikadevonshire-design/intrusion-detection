# Google Cloud IDS — Deployment & Attack Simulation Runbook

```text
┌────────────────────────────┐      ┌────────────────────────────┐      ┌────────────────────────────┐
│ 1–3. Packet Mirroring      │      │ 4. Simulate Attack Traffic │      │ 5. View Threat Alerts      │
│                            │      │                            │      │                            │
│  [Attacker VM] ──(HTTP)──> │      │  curl Shellshock / EICAR / │      │  Cloud IDS Endpoint        │
│  [Target Server VM]        │ ───> │  Log4Shell / Path Traversal│ ───> │  ──> Cloud Logging         │
│         │ (Mirrored Copy)  │      │  from ids-attacker-client  │      │  ──> Cloud Console Alerts  │
│         ▼                  │      │                            │      │                            │
│  [Cloud IDS Collector ILB] │      │                            │      │                            │
└────────────────────────────┘      └────────────────────────────┘      └────────────────────────────┘
```

## Overview of Scaffolds

| File | Purpose |
| :--- | :--- |
| [`config.yaml`](./config.yaml) | Central configuration file with `project_id: "YOUR_PROJECT_ID"` variable and settings for all 5 steps. |
| [`deploy_cloud_ids.sh`](./deploy_cloud_ids.sh) | End-to-end `gcloud` CLI orchestrator supporting `--project <PROJECT_ID>`, `--step <1..5>`, `--dry-run`, and `--cleanup`. |
| [`scripts/simulate_attacks.sh`](./scripts/simulate_attacks.sh) | **Step 4** standalone test runner that SSHes via IAP into `ids-attacker-client` and runs 5 safe exploit/malware `curl` simulations. |
| [`scripts/verify_alerts.sh`](./scripts/verify_alerts.sh) | **Step 5** standalone verification script querying `ids.googleapis.com/threat` and `ids.googleapis.com/traffic` logs in Cloud Logging. |
| [`terraform/main.tf`](./terraform/main.tf) | Declarative Terraform config for VPC, Private Services Access (PSA), Cloud IDS Endpoint, Target VMs, and Packet Mirroring Policy. |
| [`terraform/variables.tf`](./terraform/variables.tf) | Input variables with `project_id` left as a required variable to fill in. |
| [`terraform/terraform.tfvars.example`](./terraform/terraform.tfvars.example) | Example variable values (`project_id = "YOUR_PROJECT_ID"`). |
| [`terraform/outputs.tf`](./terraform/outputs.tf) | Outputs the Cloud IDS forwarding rule, VM internal IPs, and Step 4/5 CLI commands. |

---

## Quickstart: Push to Your Project

### Option A: Using the `gcloud` Orchestrator (`deploy_cloud_ids.sh`)

1. **Set your Project ID** in [`config.yaml`](./config.yaml) (or pass `--project <YOUR_PROJECT_ID>` on the command line):
   ```bash
   # Preview all commands first without making changes:
   ./deploy_cloud_ids.sh --project YOUR_PROJECT_ID --dry-run

   # Execute all 5 steps end-to-end:
   ./deploy_cloud_ids.sh --project YOUR_PROJECT_ID
   ```

2. **Run individual steps on demand**:
   ```bash
   # Step 1: Create VPC, Private Services Access, and Cloud IDS Endpoint
   ./deploy_cloud_ids.sh --project YOUR_PROJECT_ID --step 1

   # Step 2: Deploy Attacker Client VM & Target Server VM
   ./deploy_cloud_ids.sh --project YOUR_PROJECT_ID --step 2

   # Step 3: Wait for IDS Endpoint READY state & attach Packet Mirroring Policy
   ./deploy_cloud_ids.sh --project YOUR_PROJECT_ID --step 3

   # Step 4: Run safe curl attack simulations from Client VM -> Server VM
   ./scripts/simulate_attacks.sh --project YOUR_PROJECT_ID

   # Step 5: Verify threat logs in Cloud Logging
   ./scripts/verify_alerts.sh --project YOUR_PROJECT_ID --wait
   ```

---

### Option B: Using Terraform (`terraform/`)

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars to set project_id = "<YOUR_PROJECT_ID>"

terraform init
terraform plan -var="project_id=YOUR_PROJECT_ID"
terraform apply -var="project_id=YOUR_PROJECT_ID"
```

After `terraform apply` completes (Steps 1–3), run Steps 4 and 5:
```bash
cd ..
./scripts/simulate_attacks.sh --project YOUR_PROJECT_ID
./scripts/verify_alerts.sh --project YOUR_PROJECT_ID --wait
```

---

## Step-by-Step Component Breakdown & Test Cases

| Step | Component | Resource / Action | Details |
| :--- | :--- | :--- | :--- |
| **1. IDS Endpoint** | `cloud-ids-endpoint-01` | Managed Cloud IDS collector in `cloud-ids-vpc` (`us-central1-a`) | Uses Private Services Access (`servicenetworking.googleapis.com`) with `INFORMATIONAL` severity threshold and traffic logs enabled. |
| **2. Target VMs** | `ids-attacker-client` (`192.168.10.20`) & `ids-target-server` (`192.168.10.10`) | Shielded Debian 12 VMs (no external IPs, IAP SSH + Cloud NAT) | `ids-target-server` runs Apache2 and serves `/weblogin.cgi`, `/cgi-bin/test-critical`, and `/eicar.file`. |
| **3. Packet Mirroring** | `cloud-ids-packet-mirroring` | Mirrors `cloud-ids-subnet` & both VMs (`BOTH` ingress/egress) | Forwards mirrored packets to the Cloud IDS Endpoint's `endpointForwardingRule` (`--collector-ilb`). |
| **4. Attack Simulation** | [`scripts/simulate_attacks.sh`](./scripts/simulate_attacks.sh) | Executes 5 safe `curl` commands from `ids-attacker-client` | Triggers Palo Alto Networks Threat Prevention signatures across Low, Medium, High, and Critical severities:<ul><li>**TC-01 (`LOW`)**: OS Command Injection / WebLogin CGI probe</li><li>**TC-02 (`MEDIUM`)**: Directory Traversal (`../../../../WINNT/win.ini`)</li><li>**TC-03 (`HIGH`)**: GNU Bash Remote Code Execution (`Shellshock CVE-2014-6271`)</li><li>**TC-04 (`CRITICAL`)**: Apache Log4j JNDI Lookup Probe (`Log4Shell CVE-2021-44228`)</li><li>**TC-05 (`HIGH`/`CRITICAL`)**: Standard EICAR Anti-Malware Test File transfer (`/eicar.file`)</li></ul> |
| **5. Verification** | [`scripts/verify_alerts.sh`](./scripts/verify_alerts.sh) | Queries `ids.googleapis.com%2Fthreat` in Cloud Logging | Displays detected threat IDs, severities, CVEs, and attacker/target IPs, or view in Cloud Console at `https://console.cloud.google.com/net-security/ids/threats?project=<YOUR_PROJECT_ID>`. |
