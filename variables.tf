# -------- Core ----------
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "Two public subnets (AZ1, AZ2)"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.3.0/24"]
}

variable "private_subnet_cidrs" {
  description = "Two private subnets (AZ1, AZ2)"
  type        = list(string)
  default     = ["10.0.2.0/24", "10.0.4.0/24"]
}

variable "ssh_ingress_cidr" {
  description = "CIDR allowed to SSH into bastion/web"
  type        = string
  # TIP: lock this down to your IP, e.g. "203.0.113.5/32"
  default = "0.0.0.0/0"
}

variable "key_pair_name" {
  description = "Existing AWS EC2 key pair name to attach (optional)"
  type        = string
  default     = ""
}

variable "create_bastion" {
  description = "Create a bastion host in the public subnet"
  type        = bool
  default     = true
}

variable "create_nat_gateway" {
  description = "Create a managed NAT Gateway (costs $). Disable to save credits."
  type        = bool
  default     = true
}

# -------- Web / ALB / ASG --------
variable "web_instance_type" {
  description = "Instance type for web ASG"
  type        = string
  default     = "t3.micro"
}

variable "web_min_size" {
  description = "ASG min size"
  type        = number
  default     = 2
}

variable "web_desired_capacity" {
  description = "ASG desired capacity"
  type        = number
  default     = 2
}

variable "web_max_size" {
  description = "ASG max size"
  type        = number
  default     = 4
}

variable "alb_health_check_path" {
  description = "HTTP health check path"
  type        = string
  default     = "/"
}

# -------- RDS (optional) --------
variable "db_engine" {
  description = "Database engine"
  type        = string
  default     = "mysql"
}

variable "db_engine_version" {
  description = "Database engine version"
  type        = string
  default     = "8.0"
}

variable "db_instance_class" {
  description = "DB instance class"
  type        = string
  default     = "db.t3.micro"
}

variable "db_name" {
  description = "Database name"
  type        = string
  default     = "appdb"
}

variable "db_username" {
  description = "Database master username"
  type        = string
  default     = "appuser"
}

variable "db_allocated_gb" {
  description = "Allocated storage (GB)"
  type        = number
  default     = 20
}

variable "db_multi_az" {
  description = "Enable multi-AZ for RDS"
  type        = bool
  default     = false
}

variable "allow_bastion_db_access" {
  description = "Temporarily allow bastion to reach DB for debugging"
  type        = bool
  default     = false
}

# -------- Ops / Security Toggles --------
variable "enable_cloudwatch_agent" {
  description = "Install and start CloudWatch Agent on web instances"
  type        = bool
  default     = true
}

variable "enable_guardduty" {
  description = "Enable GuardDuty in this account/region"
  type        = bool
  default     = false
}

variable "enable_asg_alarms" {
  description = "Create CloudWatch alarms for the web ASG (requires web_asg to exist)"
  type        = bool
  default     = false
}

variable "enable_ssh" {
  description = "Enable SSH ingress to bastion/web"
  type        = bool
  default     = true
}

# -------- Alerts & Budgets --------
variable "alert_email" {
  description = "Email to receive alerts (leave empty to disable email subscriptions)"
  type        = string
  default     = ""
}

variable "monthly_budget_amount" {
  description = "Monthly AWS budget in USD (0 disables the Budget)"
  type        = number
  default     = 0
}

# -------- Blue/Green controls --------
variable "web_asg_blue_desired" {
  type    = number
  default = 2
}

variable "web_asg_green_desired" {
  type    = number
  default = 0
}

variable "deployment_weight_green" {
  type    = number
  default = 0 # 0..100
}

# -------- CloudTrail --------
variable "trail_bucket_days" {
  type    = number
  default = 30
}
