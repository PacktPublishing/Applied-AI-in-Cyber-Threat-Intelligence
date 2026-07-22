output "simulation_summary" {
  description = "Summary of threat simulation activities"
  value = {
    simulation_timestamp      = time_static.simulation_start.rfc3339
    project_id                = var.project_id
    region                    = var.region
    threat_actor_sa_email     = google_service_account.threat_sim_actor.email
    persistence_account_email = google_service_account.automation_account.email

    created_resources = {
      vms_created            = var.create_suspicious_vm ? 5 : 0
      firewall_rules_created = var.modify_firewall_rules ? 4 : 0
      service_accounts       = 2
      storage_buckets        = var.create_suspicious_vm ? 2 : 0
      snapshots_created      = var.create_suspicious_vm ? 2 : 0
    }

    scenario-a_ttps_simulated = [
      "T1190 - Exploit Public-Facing Application (VPN gateway + forwarding rule created)",
      "T1136.002 - Create Domain Account (itadm-suspicious SA created with editor role)",
      "T1562.001 - Impair Defenses (securitycenter.adminEditor granted)",
      "T1578.002 - Create Cloud Instance (scenario-a-rogue-instance with malicious startup script)",
      "T1562.004 - Disable Firewall (SSH/RDP rule allowing 0.0.0.0/0)",
      "T1003.001 - LSASS Memory Access (metadata server token requests in VM startup)",
      "T1490 - Inhibit System Recovery (compute snapshot deletion executed)",
      "T1219 - Remote Access Software (VM with AnyDesk metadata created)",
      "T1027.015 - Data Compression (7zip archive in GCS bucket)",
      "T1486 - Data Encrypted for Impact (scenario-a_readme.txt ransom note)"
    ]

    scattered_spider_ttps_simulated = [
      "T1110.003 - Password Spraying (5 failed SA impersonation attempts)",
      "T1087.002 - Account Discovery (gcloud iam list commands executed)",
      "T1098 - Account Manipulation (securityAdmin + serviceAccountAdmin granted)",
      var.enable_dangerous_iam_bindings ? "T1098 - CRITICAL: roles/owner granted with time condition" : "T1098 - Owner grant SKIPPED (enable_dangerous_iam_bindings=false)",
      "Firewall Modification - Management ports (443/8443/9443) opened to 0.0.0.0/0",
      "Firewall Modification - Egress to Tor network allowed",
      "OS Password Reset - Windows VM password reset for 'compromised-admin'",
      "Create SSH Backdoor - Suspicious SSH keys added to project metadata",
      "Modify Startup Script - Malicious script injected via metadata update",
      "Launch New Resources - Crypto mining VM 'xmrig-miner-*' created with c2-standard-4",
      "Data Exfiltration - Public GCS bucket created with allUsers objectViewer access"
    ]
  }
}

output "detection_hunt_queries" {
  description = "Pre-built Cloud Logging queries to detect simulated TTPs"
  value = {
    scenario-a_persistence_account = <<-EOT
      # Detect Scenario A persistence account creation (itadm-suspicious)
      resource.type="service_account"
      protoPayload.methodName="google.iam.admin.v1.CreateServiceAccount"
      protoPayload.response.email=~"itadm.*"
    EOT

    suspicious_vm_creation = <<-EOT
      # Detect VM with suspicious startup script
      resource.type="gce_instance"
      protoPayload.methodName="v1.compute.instances.insert"
      protoPayload.request.metadata.items.key="startup-script"
      (protoPayload.request.metadata.items.value=~"gcloud.*iam.*" OR
       protoPayload.request.metadata.items.value=~"curl.*metadata")
    EOT

    privilege_escalation_to_owner = <<-EOT
      # Detect roles/owner grant (Scenario B TTP)
      protoPayload.methodName="SetIamPolicy"
      protoPayload.request.policy.bindings.role="roles/owner"
      severity="NOTICE"
    EOT

    firewall_rule_0_0_0_0 = <<-EOT
      # Detect firewall rules allowing 0.0.0.0/0 access
      resource.type="gce_firewall_rule"
      protoPayload.methodName="v1.compute.firewalls.insert"
      protoPayload.request.sourceRanges="0.0.0.0/0"
    EOT

    snapshot_deletion = <<-EOT
      # Detect snapshot deletion (Scenario A data-impact inhibit recovery TTP)
      resource.type="gce_snapshot"
      protoPayload.methodName="v1.compute.snapshots.delete"
      severity="NOTICE"
    EOT

    windows_password_reset = <<-EOT
      # Detect Windows password reset (Scenario B VM takeover)
      resource.type="gce_instance"
      protoPayload.methodName=~".*setWindowsPassword"
      severity="NOTICE"
    EOT

    ssh_key_backdoor = <<-EOT
      # Detect suspicious SSH key additions to metadata
      protoPayload.methodName=~".*setMetadata"
      protoPayload.request.items.key="ssh-keys"
      (protoPayload.request.items.value=~"backdoor" OR
       protoPayload.request.items.value=~"scenario-b")
    EOT

    public_storage_bucket = <<-EOT
      # Detect GCS bucket made public (data exfiltration staging)
      resource.type="gcs_bucket"
      protoPayload.methodName="storage.setIamPermissions"
      protoPayload.serviceData.policyDelta.bindingDeltas.member="allUsers"
      protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/storage.objectViewer"
    EOT

    crypto_mining_vm = <<-EOT
      # Detect crypto mining VM creation (naming pattern + machine type)
      resource.type="gce_instance"
      protoPayload.methodName="v1.compute.instances.insert"
      (protoPayload.request.name=~".*xmrig.*" OR
       protoPayload.request.name=~".*miner.*")
      protoPayload.request.machineType=~".*c2-standard.*"
    EOT

    metadata_token_harvest = <<-EOT
      # Detect metadata server token harvesting attempts
      httpRequest.requestUrl=~".*metadata.google.internal.*service-accounts.*token"
      httpRequest.requestMethod="GET"
    EOT
  }
}

output "gcloud_hunt_commands" {
  description = "Ready-to-run gcloud commands to hunt for TTPs in Cloud Logging"
  value = {
    hunt_all_simulation_activity = <<-EOT
      gcloud logging read \
        'timestamp>="${time_static.simulation_start.rfc3339}" AND (
          protoPayload.authenticationInfo.principalEmail=~".*scenario-a.*" OR
          protoPayload.authenticationInfo.principalEmail=~".*itadm.*" OR
          resource.labels.instance_name=~".*scenario-a.*" OR
          resource.labels.instance_name=~".*xmrig.*"
        )' \
        --limit=500 \
        --format=json \
        --project=${var.project_id}
    EOT

    hunt_iam_policy_changes = <<-EOT
      gcloud logging read \
        'protoPayload.methodName="SetIamPolicy" AND
         timestamp>="${time_static.simulation_start.rfc3339}"' \
        --limit=100 \
        --format=json \
        --project=${var.project_id}
    EOT

    hunt_firewall_modifications = <<-EOT
      gcloud logging read \
        'resource.type="gce_firewall_rule" AND
         protoPayload.methodName=~".*firewalls.*" AND
         timestamp>="${time_static.simulation_start.rfc3339}"' \
        --limit=50 \
        --format=json \
        --project=${var.project_id}
    EOT

    hunt_snapshot_deletions = <<-EOT
      gcloud logging read \
        'protoPayload.methodName=~".*snapshot.*delete" AND
         timestamp>="${time_static.simulation_start.rfc3339}"' \
        --limit=50 \
        --format=json \
        --project=${var.project_id}
    EOT

    hunt_vm_creations = <<-EOT
      gcloud logging read \
        'protoPayload.methodName="v1.compute.instances.insert" AND
         timestamp>="${time_static.simulation_start.rfc3339}"' \
        --limit=100 \
        --format=json \
        --project=${var.project_id}
    EOT
  }
}

output "cleanup_instructions" {
  description = "How to remove simulation resources and verify cleanup"
  value       = <<-EOT
    === CLEANUP INSTRUCTIONS ===
    
    1. Destroy all Terraform-managed resources:
       cd gcp_threat_simulation
       terraform destroy -auto-approve
    
    2. Verify service account deletion:
       gcloud iam service-accounts list --project=${var.project_id} --filter="email~scenario-a OR email~itadm"
       # Should return empty
    
    3. Verify firewall rules removed:
       gcloud compute firewall-rules list --project=${var.project_id} --filter="name~scenario-a OR name~scenario-b"
       # Should return empty
    
    4. Verify VMs deleted:
       gcloud compute instances list --project=${var.project_id} --filter="name~scenario-a OR name~xmrig OR name~backdoor"
       # Should return empty
    
    5. Verify storage buckets deleted:
       gcloud storage buckets list --project=${var.project_id} --filter="name~scenario-a OR name~scenario-b"
       # Should return empty
    
    6. Review audit logs generated (will persist for retention period):
       gcloud logging read 'timestamp>="${time_static.simulation_start.rfc3339}"' --limit=100 --project=${var.project_id}
    
    7. Export simulation logs for golden dataset:
       gcloud logging read \
         'timestamp>="${time_static.simulation_start.rfc3339}" AND (
           protoPayload.authenticationInfo.principalEmail=~".*scenario-a.*" OR
           protoPayload.authenticationInfo.principalEmail=~".*itadm.*"
         )' \
         --format=json \
         --limit=1000 \
         --project=${var.project_id} > golden_dataset_scenario-a_${formatdate("YYYYMMDD", time_static.simulation_start.rfc3339)}.json
    
    === SIMULATION DURATION ===
    Started: ${time_static.simulation_start.rfc3339}
    Expected cleanup after: ${timeadd(time_static.simulation_start.rfc3339, "${var.simulation_duration_hours}h")}
  EOT
}

output "gcphunter_test_command" {
  description = "Command to test your GCPHunter agent against this simulation"
  value       = <<-EOT
    # After simulation is deployed, run your GCPHunter agent:
    cd ../gcphunter_agent
    python agent.py \
      --project-id ${var.project_id} \
      --start-time "${time_static.simulation_start.rfc3339}" \
      --cti-sources scenario-a_aa24-109a.md scattered_spider_wiz.md phishing_malwarebytes.md
    
    # Expected detections:
    # - T1098: Account Manipulation (roles/owner grant)
    # - T1578.002: Create Cloud Instance (5 suspicious VMs)
    # - T1562.004: Disable Firewall (4 permissive rules)
    # - T1490: Inhibit System Recovery (snapshot deletion)
    # - T1087.002: Account Discovery (IAM enumeration)
    # - T1219: Remote Access Software (AnyDesk VM)
  EOT
}

output "cost_estimate" {
  description = "Estimated cost for running this simulation"
  value       = <<-EOT
    === ESTIMATED COSTS (USD) ===
    Based on ${var.simulation_duration_hours} hour(s) runtime:
    
    - Compute Instances (5 VMs): ~$0.50/hour = $${var.simulation_duration_hours * 0.50}
    - VPN Gateway (if enabled): ~$0.05/hour = $${var.modify_firewall_rules ? var.simulation_duration_hours * 0.05 : 0}
    - Cloud Storage (2 buckets): ~$0.01 = $0.01
    - Cloud Logging (500-1000 entries): ~$0.05 = $0.05
    - Networking (egress): ~$0.10 = $0.10
    
    TOTAL ESTIMATED: ~$${var.simulation_duration_hours * 0.50 + (var.modify_firewall_rules ? var.simulation_duration_hours * 0.05 : 0) + 0.16}
    
    Note: Costs may vary. Run 'terraform destroy' promptly after testing to minimize charges.
  EOT
}