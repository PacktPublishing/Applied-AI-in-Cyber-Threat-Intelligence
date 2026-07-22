# variables.tf - GCP Threat Simulation Lab - Variable Definitions

variable "project_id" {
  description = "GCP Project ID where simulation will run (MUST BE SANDBOX/LAB ONLY)"
  type        = string

  validation {
    condition     = length(var.project_id) > 0
    error_message = "Project ID cannot be empty."
  }
}

variable "region" {
  description = "GCP region for regional resources"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone for zonal resources (e.g., VM instances)"
  type        = string
  default     = "us-central1-a"
}

variable "create_suspicious_vm" {
  description = "If true, creates a rogue VM instance for Scenario A simulation"
  type        = bool
  default     = true
}

variable "disable_logging_sinks" {
  description = "If true, simulate log sink manipulation (detection evasion technique)"
  type        = bool
  default     = false
}

variable "enable_scenario-a_simulation" {
  description = "Enable Scenario A data-impact TTPs simulation"
  type        = bool
  default     = true
}

variable "enable_scattered_spider_simulation" {
  description = "Enable Scenario B TTPs simulation"
  type        = bool
  default     = false
}

variable "vm_machine_type" {
  description = "Machine type for simulation VMs"
  type        = string
  default     = "e2-medium"
}

variable "allow_destroy" {
  description = "Safety flag - must be true to allow terraform destroy"
  type        = bool
  default     = false
}

variable "simulation_duration_hours" {
  description = "Expected duration of simulation in hours (for documentation)"
  type        = number
  default     = 4
}

variable "alert_email" {
  description = "Email address for simulation alerts (optional)"
  type        = string
  default     = ""
}

variable "network_cidr" {
  description = "CIDR block for simulation network"
  type        = string
  default     = "10.200.0.0/16"
}

variable "subnet_cidr" {
  description = "CIDR block for simulation subnet"
  type        = string
  default     = "10.200.1.0/24"
}

variable "modify_firewall_rules" {
  description = "If true, creates risky firewall rules (T1562.004 - Impair Defenses: Disable or Modify Firewall)"
  type        = bool
  default     = false
}

variable "enable_dangerous_iam_bindings" {
  description = "If true, creates dangerous IAM bindings for privilege escalation simulation (REQUIRES CAUTION)"
  type        = bool
  default     = false
}

variable "simulate_credential_access" {
  description = "If true, simulates credential access techniques (password spray, IAM enumeration)"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Additional tags/labels for all resources"
  type        = map(string)
  default = {
    environment = "threat-simulation"
    managed-by  = "terraform"
    purpose     = "security-testing"
  }
}