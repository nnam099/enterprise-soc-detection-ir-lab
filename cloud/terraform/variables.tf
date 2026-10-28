variable "region" {
  description = "AWS region"
  type        = string
  default     = "ap-southeast-2"
}

variable "project" {
  description = "Stack name prefix"
  type        = string
  default     = "soc-hybrid"
}

variable "environment" {
  description = "Environment tag"
  type        = string
  default     = "lab"
}

variable "vpc_cidr" {
  description = "Lab VPC CIDR"
  type        = string
  default     = "10.20.0.0/16"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "ssh_key_name" {
  description = "Optional EC2 key pair name"
  type        = string
  default     = ""
}

variable "wazuh_manager_ip" {
  description = "Wazuh manager Tailscale IP (100.x.y.z)"
  type        = string
  default     = ""
}

variable "wazuh_agent_name" {
  description = "Wazuh agent name for the EC2 host"
  type        = string
  default     = "SOC-AWS-01"
}

variable "wazuh_registration_password" {
  description = "Wazuh authd enrollment password"
  type        = string
  sensitive   = true
  default     = ""
}

variable "tailscale_authkey" {
  description = "Tailscale auth key"
  type        = string
  sensitive   = true
  default     = ""
}

variable "log_retention_days" {
  description = "S3 log retention in days"
  type        = number
  default     = 90
}
