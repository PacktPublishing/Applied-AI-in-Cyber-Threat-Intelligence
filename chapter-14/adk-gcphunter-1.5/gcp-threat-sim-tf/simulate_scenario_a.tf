# ==============================================================================
# GENERIC INFRASTRUCTURE DEPLOYMENT
# ==============================================================================

# ------------------------------------------------------------------------------
# NETWORK INFRASTRUCTURE
# ------------------------------------------------------------------------------
resource "google_compute_network" "app_network" {
  name                    = "app-network-vpc"
  auto_create_subnetworks = false
  description             = "Application network for workload deployment"
}

resource "google_compute_subnetwork" "app_subnet" {
  name          = "app-subnet-primary"
  ip_cidr_range = "10.128.0.0/20"
  region        = var.region
  network       = google_compute_network.app_network.id

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 1.0
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# ------------------------------------------------------------------------------
# SERVICE ACCOUNTS (Will trigger T1098.004 detection)
# ------------------------------------------------------------------------------
resource "google_service_account" "automation_account" {
  account_id   = "sa-automation-${random_id.simulation_id.hex}"
  display_name = "Automation Service Account"
  description  = "Service account for automated deployment workflows"
}

# Grant project-level permissions (Will trigger T1484.002 - SetIamPolicy detection)
resource "google_project_iam_member" "automation_editor" {
  project = var.project_id
  role    = "roles/editor"
  member  = "serviceAccount:${google_service_account.automation_account.email}"
}

resource "google_project_iam_member" "automation_compute" {
  project = var.project_id
  role    = "roles/compute.admin"
  member  = "serviceAccount:${google_service_account.automation_account.email}"
}

# Create service account key
resource "google_service_account_key" "automation_key" {
  service_account_id = google_service_account.automation_account.name
}

# ------------------------------------------------------------------------------
# LOGGING SINK (Will trigger T1562.008 detection)
# ------------------------------------------------------------------------------
resource "google_logging_project_sink" "app_logs_export" {
  count       = var.disable_logging_sinks ? 1 : 0
  name        = "app-logs-export"
  destination = "storage.googleapis.com/${google_storage_bucket.log_export_bucket[0].name}"

  # Filter that excludes sensitive operations
  filter = "NOT (protoPayload.methodName=~\".*SetIamPolicy.*\" OR protoPayload.methodName=~\".*delete.*\")"

  unique_writer_identity = true
}

resource "google_storage_bucket" "log_export_bucket" {
  count    = var.disable_logging_sinks ? 1 : 0
  name     = "${var.project_id}-logs-export-${random_id.simulation_id.hex}"
  location = var.region

  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      age = 7
    }
  }
}

# ------------------------------------------------------------------------------
# STORAGE BUCKETS
# ------------------------------------------------------------------------------
resource "google_storage_bucket" "application_data" {
  name     = "${var.project_id}-app-data-${random_id.simulation_id.hex}"
  location = var.region

  uniform_bucket_level_access = true

  labels = {
    environment = "production"
    application = "data-processing"
  }
}

# Upload sample data files
resource "google_storage_bucket_object" "data_files" {
  for_each = toset([
    "dataset_2024.csv",
    "config.json",
    "backup.tar.gz",
    "reports_q4.pdf"
  ])

  name    = "data/${each.key}"
  bucket  = google_storage_bucket.application_data.name
  content = "Sample application data for processing workflows"
}

# ------------------------------------------------------------------------------
# COMPUTE DISK AND SNAPSHOT
# ------------------------------------------------------------------------------
resource "google_compute_disk" "data_disk" {
  count = var.create_suspicious_vm ? 1 : 0
  name  = "app-data-disk-${random_id.simulation_id.hex}"
  type  = "pd-standard"
  zone  = var.zone
  size  = 10

  labels = {
    environment = "production"
    purpose     = "data-storage"
  }
}

resource "google_compute_snapshot" "data_backup" {
  count       = var.create_suspicious_vm ? 1 : 0
  name        = "backup-${formatdate("YYYYMMDD-hhmmss", time_static.simulation_start.rfc3339)}"
  source_disk = google_compute_disk.data_disk[0].name
  zone        = var.zone

  storage_locations = [var.region]
}

# ------------------------------------------------------------------------------
# COMPUTE INSTANCES WITH STARTUP SCRIPTS (Will trigger T1525 detection)
# ------------------------------------------------------------------------------

# Processing worker VM
resource "google_compute_instance" "worker_vm" {
  count        = var.create_suspicious_vm ? 1 : 0
  name         = "worker-vm-${random_id.simulation_id.hex}"
  machine_type = "e2-micro"
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.app_subnet.id
  }

  # Startup script will trigger T1525 detection
  metadata = {
    startup-script = <<-EOT
      #!/bin/bash
      # Application worker initialization
      apt-get update
      apt-get install -y python3-pip curl wget

      # Download processing scripts
      mkdir -p /opt/worker
      curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -

      # Configure worker service
      cat > /etc/systemd/system/worker.service <<'EOF'
[Unit]
Description=Data Processing Worker
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/worker/process.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

      systemctl daemon-reload
      systemctl enable worker.service
    EOT
  }

  service_account {
    email  = google_service_account.automation_account.email
    scopes = ["cloud-platform"]
  }

  labels = {
    role        = "worker"
    environment = "production"
  }
}

# Data processor VM
resource "google_compute_instance" "processor_vm" {
  count        = var.create_suspicious_vm ? 1 : 0
  name         = "data-processor-${random_id.simulation_id.hex}"
  machine_type = "e2-small"
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.app_subnet.id
    access_config {
      # Ephemeral public IP
    }
  }

  # Startup script will trigger T1525 detection
  metadata = {
    enable-oslogin = "TRUE"
    startup-script = <<-EOT
      #!/bin/bash
      # Data processor initialization
      echo "Initializing data processor" > /var/log/init.log

      # Install dependencies
      apt-get update && apt-get install -y \
        docker.io \
        docker-compose \
        netcat \
        nmap

      # Configure container runtime
      systemctl start docker
      systemctl enable docker

      # Download processor image
      docker pull gcr.io/google.com/cloudsdktool/google-cloud-cli:latest

      # Network connectivity check
      nc -zv 8.8.8.8 443 || true

      # Service discovery
      for port in 22 80 443 3306 5432; do
        nc -zv -w 1 10.128.0.1 $port || true
      done
    EOT
  }

  service_account {
    email  = google_service_account.automation_account.email
    scopes = ["cloud-platform"]
  }

  labels = {
    role        = "processor"
    environment = "production"
  }
}

# App server VM
resource "google_compute_instance" "app_server" {
  count        = var.create_suspicious_vm ? 1 : 0
  name         = "app-server-${random_id.simulation_id.hex}"
  machine_type = "e2-medium"
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.app_subnet.id
    access_config {}
  }

  # Startup script will trigger T1525 detection
  metadata = {
    startup-script = <<-EOT
      #!/bin/bash
      # Application server setup
      apt-get update
      apt-get install -y nginx certbot python3-certbot-nginx

      # Configure web server
      cat > /etc/nginx/sites-available/default <<'NGINX'
server {
    listen 80 default_server;
    server_name _;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
NGINX

      # Download application
      mkdir -p /opt/app
      cd /opt/app
      wget -q https://storage.googleapis.com/app-releases/latest.tar.gz || true
      tar -xzf latest.tar.gz || true

      # Start services
      systemctl restart nginx
      systemctl enable nginx
    EOT
  }

  service_account {
    email  = google_service_account.automation_account.email
    scopes = ["cloud-platform"]
  }

  labels = {
    role        = "web-server"
    environment = "production"
  }
}

# ------------------------------------------------------------------------------
# FIREWALL RULES
# ------------------------------------------------------------------------------
resource "google_compute_firewall" "allow_https_egress" {
  count   = var.modify_firewall_rules ? 1 : 0
  name    = "allow-https-egress"
  network = google_compute_network.app_network.name

  description = "Allow HTTPS egress for package downloads"
  direction   = "EGRESS"

  allow {
    protocol = "tcp"
    ports    = ["443", "8443", "9443"]
  }

  destination_ranges = ["0.0.0.0/0"]

  target_tags = ["web-server", "worker"]

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "allow_ssh_ingress" {
  count   = var.modify_firewall_rules ? 1 : 0
  name    = "allow-ssh-ingress"
  network = google_compute_network.app_network.name

  description = "Allow SSH access for management"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]

  target_tags = ["management"]

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# ------------------------------------------------------------------------------
# STAGING BUCKET
# ------------------------------------------------------------------------------
resource "google_storage_bucket" "staging_bucket" {
  count    = var.create_suspicious_vm ? 1 : 0
  name     = "staging-${var.project_id}-${random_id.simulation_id.hex}"
  location = var.region

  uniform_bucket_level_access = false

  labels = {
    purpose     = "staging"
    environment = "production"
  }

  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      age = 7
    }
  }
}

# Upload deployment artifacts
resource "google_storage_bucket_object" "deployment_package" {
  count   = var.create_suspicious_vm ? 1 : 0
  name    = "deployments/release_${formatdate("YYYYMMDD_HHmmss", time_static.simulation_start.rfc3339)}.tar.gz"
  bucket  = google_storage_bucket.staging_bucket[0].name
  content = base64encode("Deployment package contents")

  metadata = {
    version      = "1.0.0"
    release_date = formatdate("YYYY-MM-DD", time_static.simulation_start.rfc3339)
    environment  = "production"
  }
}
