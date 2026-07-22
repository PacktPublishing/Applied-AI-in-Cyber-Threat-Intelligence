# main.tf - GCP Threat Simulation Lab - Core Infrastructure

terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.9"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

# Generate unique simulation ID for resource naming
resource "random_id" "simulation_id" {
  byte_length = 4
}

# Capture simulation start time
resource "time_static" "simulation_start" {}

# Threat simulation actor service account (shared across simulations)
resource "google_service_account" "threat_sim_actor" {
  account_id   = "adk-th-sim-actor-${random_id.simulation_id.hex}"
  display_name = "Threat Simulation Actor"
  description  = "Service account used for threat simulation activities"
}

# Grant basic permissions to threat simulation actor
resource "google_project_iam_member" "threat_sim_viewer" {
  project = var.project_id
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.threat_sim_actor.email}"
}

resource "google_project_iam_member" "threat_sim_compute_viewer" {
  project = var.project_id
  role    = "roles/compute.viewer"
  member  = "serviceAccount:${google_service_account.threat_sim_actor.email}"
}

# Logging bucket for simulation events
resource "google_storage_bucket" "simulation_logs" {
  name          = "${var.project_id}-threat-sim-logs-${random_id.simulation_id.hex}"
  location      = var.region
  force_destroy = true

  uniform_bucket_level_access = true

  labels = {
    purpose    = "threat-simulation"
    managed-by = "terraform"
    created    = formatdate("YYYY-MM-DD", time_static.simulation_start.rfc3339)
  }

  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type = "Delete"
    }
  }
}

# Simulation metadata tracking
resource "null_resource" "simulation_metadata" {
  provisioner "local-exec" {
    command = "echo Simulation ID: ${random_id.simulation_id.hex} started at ${time_static.simulation_start.rfc3339}"
  }
}