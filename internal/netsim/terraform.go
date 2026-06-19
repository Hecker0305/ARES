package netsim

import (
	"github.com/ares/engine/internal/uuid"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"text/template"
	"time"
)

type CloudProvider string

const (
	ProviderAWS   CloudProvider = "aws"
	ProviderAzure CloudProvider = "azure"
	ProviderGCP   CloudProvider = "gcp"
	ProviderLocal CloudProvider = "local"
)

type TerraformConfig struct {
	ID            string        `json:"id"`
	SimulationID  string        `json:"simulation_id"`
	Provider      CloudProvider `json:"provider"`
	Region        string        `json:"region"`
	InstanceCount int           `json:"instance_count"`
	InstanceType  string        `json:"instance_type"`
	Status        string        `json:"status"`
	OutputDir     string        `json:"output_dir"`
	CreatedAt     time.Time     `json:"created_at"`
	DeployedAt    time.Time     `json:"deployed_at,omitempty"`
	DestroyedAt   time.Time     `json:"destroyed_at,omitempty"`
	PublicIPs     []string      `json:"public_ips,omitempty"`
}

type terraformManager struct {
	mu      sync.RWMutex
	configs map[string]*TerraformConfig
	workDir string
}

func newTerraformManager(workDir string) *terraformManager {
	return &terraformManager{
		configs: make(map[string]*TerraformConfig),
		workDir: workDir,
	}
}

func (tm *terraformManager) Generate(simID string, provider CloudProvider, region string, count int, instanceType string) (*TerraformConfig, error) {
	id := uuid.New()
	outputDir := filepath.Join(tm.workDir, "terraform", id)

	cfg := &TerraformConfig{
		ID:            id,
		SimulationID:  simID,
		Provider:      provider,
		Region:        region,
		InstanceCount: count,
		InstanceType:  instanceType,
		Status:        "generated",
		OutputDir:     outputDir,
		CreatedAt:     time.Now(),
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("create terraform dir: %w", err)
	}

	if err := tm.writeTerraformFiles(cfg); err != nil {
		return nil, fmt.Errorf("write terraform files: %w", err)
	}

	tm.mu.Lock()
	tm.configs[id] = cfg
	tm.mu.Unlock()
	return cfg, nil
}

func (tm *terraformManager) writeTerraformFiles(cfg *TerraformConfig) error {
	// main.tf
	mainTpl := tm.getMainTemplate(cfg.Provider)
	mainFile := filepath.Join(cfg.OutputDir, "main.tf")
	f, err := os.Create(mainFile)
	if err != nil {
		return err
	}
	defer f.Close()

	tpl, err := template.New("main").Parse(mainTpl)
	if err != nil {
		return err
	}
	return tpl.Execute(f, map[string]interface{}{
		"Region":        cfg.Region,
		"InstanceCount": cfg.InstanceCount,
		"InstanceType":  cfg.InstanceType,
		"SimulationID":  cfg.SimulationID,
	})
}

func (tm *terraformManager) getMainTemplate(provider CloudProvider) string {
	switch provider {
	case ProviderAWS:
		return awsTemplate
	case ProviderAzure:
		return azureTemplate
	case ProviderGCP:
		return gcpTemplate
	default:
		return localTemplate
	}
}

func (tm *terraformManager) Init(id string) error {
	cfg := tm.Get(id)
	if cfg == nil {
		return fmt.Errorf("config %s not found", id)
	}
	cmd := exec.Command("terraform", "init")
	cmd.Dir = cfg.OutputDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("terraform init: %s: %v", string(output), err)
	}
	cfg.Status = "initialized"
	return nil
}

func (tm *terraformManager) Apply(id string) error {
	cfg := tm.Get(id)
	if cfg == nil {
		return fmt.Errorf("config %s not found", id)
	}
	cmd := exec.Command("terraform", "apply", "-auto-approve")
	cmd.Dir = cfg.OutputDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("terraform apply: %s: %v", string(output), err)
	}

	cfg.Status = "deployed"
	cfg.DeployedAt = time.Now()

	// Try to extract outputs
	if ips := tm.extractOutputs(cfg.OutputDir); len(ips) > 0 {
		cfg.PublicIPs = ips
	}
	return nil
}

func (tm *terraformManager) Destroy(id string) error {
	cfg := tm.Get(id)
	if cfg == nil {
		return fmt.Errorf("config %s not found", id)
	}
	cmd := exec.Command("terraform", "destroy", "-auto-approve")
	cmd.Dir = cfg.OutputDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("terraform destroy: %s: %v", string(output), err)
	}
	cfg.Status = "destroyed"
	cfg.DestroyedAt = time.Now()
	return nil
}

func (tm *terraformManager) extractOutputs(dir string) []string {
	cmd := exec.Command("terraform", "output", "-json")
	cmd.Dir = dir
	output, err := cmd.Output()
	if err != nil {
		return nil
	}
	var outputs map[string]interface{}
	if json.Unmarshal(output, &outputs) != nil {
		return nil
	}
	var ips []string
	if pubIPs, ok := outputs["public_ips"]; ok {
		if vals, ok := pubIPs.(map[string]interface{}); ok {
			if val, ok := vals["value"]; ok {
				if arr, ok := val.([]interface{}); ok {
					for _, v := range arr {
						if s, ok := v.(string); ok {
							ips = append(ips, s)
						}
					}
				}
			}
		}
	}
	return ips
}

func (tm *terraformManager) Get(id string) *TerraformConfig {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.configs[id]
}

func (tm *terraformManager) List() []*TerraformConfig {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	result := make([]*TerraformConfig, 0, len(tm.configs))
	for _, c := range tm.configs {
		result = append(result, c)
	}
	return result
}

// Terraform HCL templates

const awsTemplate = `
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "region" {
  default = "{{.Region}}"
}

provider "aws" {
  region = var.region
}

resource "aws_security_group" "simulation" {
  name        = "ares-sim-{{.SimulationID}}"
  description = "Ares network simulation security group"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "ares-sim-{{.SimulationID}}"
    Simulation  = "{{.SimulationID}}"
    Environment = "ares-pentest"
  }
}

resource "aws_instance" "simulation_target" {
  count         = {{.InstanceCount}}
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "{{.InstanceType}}"
  key_name      = "ares-sim-key"

  vpc_security_group_ids = [aws_security_group.simulation.id]

  user_data = <<-EOF
    #!/bin/bash
    apt-get update
    apt-get install -y python3 python3-pip iperf3 netcat-openbsd
    pip3 install scapy
    echo "Ares simulation target ready" > /etc/motd
  EOF

  tags = {
    Name        = "ares-target-${count.index}"
    Simulation  = "{{.SimulationID}}"
    Environment = "ares-pentest"
  }
}

output "public_ips" {
  value = aws_instance.simulation_target[*].public_ip
}
`

const azureTemplate = `
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

variable "location" {
  default = "{{.Region}}"
}

resource "azurerm_resource_group" "sim" {
  name     = "ares-sim-{{.SimulationID}}"
  location = var.location

  tags = {
    Simulation = "{{.SimulationID}}"
  }
}

resource "azurerm_virtual_network" "sim" {
  name                = "ares-sim-net-{{.SimulationID}}"
  resource_group_name = azurerm_resource_group.sim.name
  location            = var.location
  address_space       = ["10.0.0.0/16"]
}

resource "azurerm_subnet" "sim" {
  name                 = "ares-sim-subnet"
  resource_group_name  = azurerm_resource_group.sim.name
  virtual_network_name = azurerm_virtual_network.sim.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_network_security_group" "sim" {
  name                = "ares-sim-nsg"
  resource_group_name = azurerm_resource_group.sim.name
  location            = var.location

  security_rule {
    name                       = "ALLOW_ALL"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefixes    = ["0.0.0.0/0"]
    destination_address_prefix = "*"
  }
}

resource "azurerm_public_ip" "sim" {
  count               = {{.InstanceCount}}
  name                = "ares-sim-pip-${count.index}"
  resource_group_name = azurerm_resource_group.sim.name
  location            = var.location
  allocation_method   = "Static"
}

resource "azurerm_network_interface" "sim" {
  count               = {{.InstanceCount}}
  name                = "ares-sim-nic-${count.index}"
  resource_group_name = azurerm_resource_group.sim.name
  location            = var.location

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.sim.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.sim[count.index].id
  }
}

resource "azurerm_linux_virtual_machine" "sim" {
  count               = {{.InstanceCount}}
  name                = "ares-sim-vm-${count.index}"
  resource_group_name = azurerm_resource_group.sim.name
  location            = var.location
  size                = "{{.InstanceType}}"
  admin_username      = "ares"

  network_interface_ids = [
    azurerm_network_interface.sim[count.index].id,
  ]

  admin_ssh_key {
    username   = "ares"
    public_key = file("~/.ssh/id_rsa.pub")
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }

  tags = {
    Simulation = "{{.SimulationID}}"
  }
}

output "public_ips" {
  value = azurerm_public_ip.sim[*].ip_address
}
`

const gcpTemplate = `
terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  region = "{{.Region}}"
}

resource "google_compute_network" "sim" {
  name                    = "ares-sim-net-{{.SimulationID}}"
  auto_create_subnetworks = true
}

resource "google_compute_firewall" "sim" {
  name    = "ares-sim-fw-{{.SimulationID}}"
  network = google_compute_network.sim.name

  allow {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_instance" "sim" {
  count        = {{.InstanceCount}}
  name         = "ares-sim-{{.SimulationID}}-${count.index}"
  machine_type = "{{.InstanceType}}"
  zone         = "{{.Region}}-a"

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
    }
  }

  network_interface {
    network = google_compute_network.sim.name
    access_config {}
  }

  metadata = {
    simulation = "{{.SimulationID}}"
  }

  tags = ["ares-sim"]
}

output "public_ips" {
  value = google_compute_instance.sim[*].network_interface[0].access_config[0].nat_ip
}
`

const localTemplate = `
provider "local" {}

resource "local_file" "sim_config" {
  filename = "${path.module}/sim-{{.SimulationID}}.cfg"
  content  = <<-EOF
    [simulation]
    id = {{.SimulationID}}
    targets = {{.InstanceCount}}
    timestamp = "${timestamp()}"
  EOF
}
`
