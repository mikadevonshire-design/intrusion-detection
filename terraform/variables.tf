variable "project_id" {
  description = "Target Google Cloud Project ID where Cloud IDS and test infrastructure will be deployed"
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id)) && var.project_id != "your-project-id"
    error_message = "Please provide a valid GCP project_id (6-30 lowercase letters, digits, or hyphens)."
  }
}

variable "region" {
  description = "GCP region for VPC subnet and Packet Mirroring policy"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone for the Cloud IDS Endpoint and Target VMs"
  type        = string
  default     = "us-central1-a"
}

variable "vpc_name" {
  description = "Name of the target VPC network for Cloud IDS"
  type        = string
  default     = "cloud-ids-vpc"
}

variable "subnet_name" {
  description = "Name of the target subnetwork to mirror"
  type        = string
  default     = "cloud-ids-subnet"
}

variable "subnet_cidr" {
  description = "CIDR block for the mirrored subnetwork"
  type        = string
  default     = "192.168.10.0/24"
}

variable "ids_endpoint_name" {
  description = "Name of the managed Cloud IDS endpoint collector"
  type        = string
  default     = "cloud-ids-endpoint-01"
}

variable "ids_severity" {
  description = "Minimum threat severity level for Cloud IDS alerts (INFORMATIONAL, LOW, MEDIUM, HIGH)"
  type        = string
  default     = "INFORMATIONAL"
}

variable "threat_exceptions" {
  description = "Optional list of threat IDs to exclude from alerting"
  type        = list(string)
  default     = []
}

variable "server_vm_name" {
  description = "Name of the target server VM hosting HTTP test endpoints"
  type        = string
  default     = "ids-target-server"
}

variable "server_internal_ip" {
  description = "Static internal IP for the target server VM"
  type        = string
  default     = "192.168.10.10"
}

variable "client_vm_name" {
  description = "Name of the attacker client VM running safe exploit simulation curl requests"
  type        = string
  default     = "ids-attacker-client"
}

variable "client_internal_ip" {
  description = "Static internal IP for the attacker client VM"
  type        = string
  default     = "192.168.10.20"
}

variable "packet_mirroring_name" {
  description = "Name of the Packet Mirroring policy forwarding traffic to the Cloud IDS endpoint"
  type        = string
  default     = "cloud-ids-packet-mirroring"
}
