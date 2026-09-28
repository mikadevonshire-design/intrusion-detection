output "project_id" {
  description = "Deployed GCP Project ID"
  value       = var.project_id
}

output "ids_endpoint_name" {
  description = "Step 1: Cloud IDS Endpoint Name"
  value       = google_cloud_ids_endpoint.ids_endpoint.name
}

output "ids_endpoint_forwarding_rule" {
  description = "Step 1: Cloud IDS Collector ILB Forwarding Rule URL used by Packet Mirroring"
  value       = google_cloud_ids_endpoint.ids_endpoint.endpoint_forwarding_rule
}

output "target_server_vm_internal_ip" {
  description = "Step 2: Internal IP address of the Target Server VM"
  value       = google_compute_instance.target_server_vm.network_interface[0].network_ip
}

output "attacker_client_vm_internal_ip" {
  description = "Step 2: Internal IP address of the Attacker Client VM"
  value       = google_compute_instance.attacker_client_vm.network_interface[0].network_ip
}

output "packet_mirroring_policy_id" {
  description = "Step 3: Packet Mirroring Policy ID"
  value       = google_compute_packet_mirroring.ids_packet_mirroring.id
}

output "step_4_attack_simulation_command" {
  description = "Step 4: Command to trigger safe attack simulations from the Client VM via IAP SSH"
  value       = "gcloud compute ssh ${google_compute_instance.attacker_client_vm.name} --project=${var.project_id} --zone=${var.zone} --tunnel-through-iap --command='/usr/local/bin/run_ids_attack_sim.sh ${google_compute_instance.target_server_vm.network_interface[0].network_ip}'"
}

output "step_5_verify_threat_logs_command" {
  description = "Step 5: Command to view Cloud IDS threat alerts in Cloud Logging"
  value       = "gcloud logging read 'resource.type=\"ids.googleapis.com/Endpoint\" AND logName:\"ids.googleapis.com%2Fthreat\"' --project=${var.project_id} --limit=20"
}
