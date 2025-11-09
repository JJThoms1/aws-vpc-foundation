############################################
# Data lookups
############################################
data "aws_availability_zones" "available" {
  state = "available"
}

# Amazon Linux 2023 AMI (x86_64)
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["137112412989"] # Amazon
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

############################################
# Networking: VPC, Subnets, IGW, Routes, NAT
############################################
resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "vpc-foundation" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "vpc-foundation-igw" }
}

# Two public subnets across first 2 AZs
resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  tags                    = { Name = "public-${count.index + 1}", Tier = "public" }
}

# Two private subnets across first 2 AZs
resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags              = { Name = "private-${count.index + 1}", Tier = "private" }
}

# Public route table with default route to Internet
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "public-rt" }
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route_table_association" "public_assoc" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# NAT (optional to save credits)
resource "aws_eip" "nat" {
  count  = var.create_nat_gateway ? 1 : 0
  domain = "vpc"
  tags   = { Name = "nat-eip" }
}

resource "aws_nat_gateway" "this" {
  count         = var.create_nat_gateway ? 1 : 0
  subnet_id     = aws_subnet.public[0].id
  allocation_id = aws_eip.nat[0].id
  tags          = { Name = "vpc-foundation-nat" }
  depends_on    = [aws_internet_gateway.igw]
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "private-rt" }
}

# Private default route to NAT (only when NAT enabled)
resource "aws_route" "private_nat" {
  count                  = var.create_nat_gateway ? 1 : 0
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[0].id
}

resource "aws_route_table_association" "private_assoc" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

############################################
# Security Groups
############################################
# Public-facing SG (bastion)
resource "aws_security_group" "public_sg" {
  name        = "public-sg"
  description = "Allow SSH/HTTP from internet (lock SSH to your IP in prod)"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.ssh_ingress_cidr]
  }
  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }


  tags = { Name = "public-sg" }
}

# Private SG (app) - only SSH from public_sg
resource "aws_security_group" "private_sg" {
  name        = "private-sg"
  description = "Allow SSH from public_sg, outbound to internet/NAT"
  vpc_id      = aws_vpc.this.id

  dynamic "ingress" {
    for_each = var.enable_ssh ? [1] : []
    content {
      description = "SSH"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = [var.ssh_ingress_cidr]
    }
  }


  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "private-sg" }
}

# ALB SG - public HTTP
resource "aws_security_group" "alb_sg" {
  name        = "alb-sg"
  description = "Allow HTTP from anywhere to ALB"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "HTTP from internet"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "alb-sg" }
}

# Web tier SG - HTTP from ALB, optional SSH from bastion
resource "aws_security_group" "web_sg" {
  name        = "web-sg"
  description = "Allow HTTP from ALB and SSH from bastion/public_sg"
  vpc_id      = aws_vpc.this.id

  ingress {
    description     = "HTTP from ALB"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }
  dynamic "ingress" {
    for_each = var.enable_ssh ? [1] : []
    content {
      description     = "SSH from public_sg (bastion)"
      from_port       = 22
      to_port         = 22
      protocol        = "tcp"
      security_groups = [aws_security_group.public_sg.id]
    }
  }


  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "web-sg" }
}

############################################
# EC2 Instances: Bastion (public) & App (private)
############################################
locals { common_tags = { Project = "vpc-foundation" } }

resource "aws_instance" "bastion" {
  count                       = var.create_bastion ? 1 : 0
  ami                         = data.aws_ami.al2023.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public[0].id
  vpc_security_group_ids      = [aws_security_group.public_sg.id]
  associate_public_ip_address = true
  key_name                    = var.key_pair_name != "" ? var.key_pair_name : null
  tags                        = merge(local.common_tags, { Name = "bastion" })

  user_data            = <<-EOF
    #!/bin/bash
    dnf -y update
  EOF
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name
}

resource "aws_instance" "app" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.private[0].id
  vpc_security_group_ids = [aws_security_group.private_sg.id]
  key_name               = var.key_pair_name != "" ? var.key_pair_name : null
  tags                   = merge(local.common_tags, { Name = "app" })
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name
}

############################################
# ALB in public subnets
############################################
resource "aws_lb" "web_alb" {
  name               = "web-alb"
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = [aws_subnet.public[0].id, aws_subnet.public[1].id]
  idle_timeout       = 60
  tags               = { Name = "web-alb" }
  access_logs {
    bucket  = aws_s3_bucket.alb_logs.bucket
    prefix  = "alb"
    enabled = true
  }
}

# --- LISTENER  ---
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.web_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "forward"
    forward {
      target_group {
        arn    = aws_lb_target_group.web_tg_blue.arn
        weight = 100 - var.deployment_weight_green
      }
      target_group {
        arn    = aws_lb_target_group.web_tg_green.arn
        weight = var.deployment_weight_green
      }

      # <-- add duration even if enabled=false
      stickiness {
        enabled  = false
        duration = 300
      }
    }
  }
}

resource "aws_lb_target_group" "web_tg_blue" {
  name        = "web-tg-blue"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.this.id
  target_type = "instance"

  health_check {
    enabled = true
    path    = "/"
    matcher = "200-399"
  }

  tags = { Env = "blue" }
}

resource "aws_lb_target_group" "web_tg_green" {
  name        = "web-tg-green"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.this.id
  target_type = "instance"

  health_check {
    enabled = true
    path    = "/"
    matcher = "200-399"
  }

  tags = { Env = "green" }
}


############################################
# IAM for EC2 (CloudWatch Agent + SSM + Secrets)
############################################
data "aws_iam_policy" "cw_agent_policy" { arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy" }
data "aws_iam_policy" "ssm_core" { arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore" }

resource "aws_iam_role" "ec2_role" {
  name = "vpc-foundation-ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "attach_cw_agent" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = data.aws_iam_policy.cw_agent_policy.arn
}

resource "aws_iam_role_policy_attachment" "attach_ssm" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = data.aws_iam_policy.ssm_core.arn
}

# Allow web instances to read the DB secret
resource "aws_iam_role_policy" "ec2_read_db_secret" {
  name = "read-db-secret"
  role = aws_iam_role.ec2_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = ["secretsmanager:GetSecretValue"],
      Resource = aws_secretsmanager_secret.db_secret.arn
    }]
  })
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "vpc-foundation-ec2-profile"
  role = aws_iam_role.ec2_role.name
}

############################################
# Launch Template + Auto Scaling Group (web)
############################################
resource "aws_cloudwatch_log_group" "web" {
  name              = "/vpc-foundation/web"
  retention_in_days = 30
}

resource "aws_launch_template" "web_lt" {
  name_prefix   = "web-lt-"
  image_id      = data.aws_ami.al2023.id
  instance_type = var.web_instance_type
  key_name      = var.key_pair_name != "" ? var.key_pair_name : null

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_profile.name
  }

  # Use only network_interfaces for SGs
  network_interfaces {
    device_index                = 0
    associate_public_ip_address = false
    security_groups             = [aws_security_group.web_sg.id]
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 2
    http_tokens                 = "required"
  }

  # --- INLINE USER DATA (note the closing EOT and ) ) ---
  user_data = base64encode(<<-EOT
    #!/bin/bash
    set -euxo pipefail

    # ---------- Basics ----------
    dnf -y update
    dnf -y install nginx python3 python3-pip awscli
    python3 -m pip install --upgrade pip
    python3 -m pip install flask pymysql boto3 gunicorn

    # ---------- Inputs from Terraform ----------
    DB_HOST="$${aws_db_instance.mysql.address}"

    # ---------- Fetch DB credentials from Secrets Manager (with IMDSv2)----------
    TOKEN=$(curl -sS -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
    REGION="$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | awk -F'"' '/region/ {print $4}')"
    SECRET_NAME="vpc-foundation-db-credentials"
    SECRET_ID="$(aws secretsmanager list-secrets --region "$REGION" \
      --filters Key=name,Values=$SECRET_NAME \
      --query 'SecretList | sort_by(@, &LastChangedDate)[-1].Name' --output text || true)"
    if [ -z "$SECRET_ID" ] || [ "$SECRET_ID" = "None" ]; then
      SECRET_ID="$(aws secretsmanager list-secrets --region "$REGION" \
        --query "SecretList[?starts_with(Name, '$SECRET_NAME')].Name | [-1]" --output text || true)"
    fi
    SECRET_JSON="$(aws secretsmanager get-secret-value --region "$REGION" --secret-id "$SECRET_ID" --query SecretString --output text || echo '{}')"

    DB_USER="$(echo "$SECRET_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("username",""))')"
    DB_PASS="$(echo "$SECRET_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("password",""))')"
    DB_NAME="$(echo "$SECRET_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("dbname",""))')"

    # ---------- App files ----------
    mkdir -p /opt/app

    cat >/opt/app/app.py <<'PY'
import os
from flask import Flask
import pymysql

app = Flask(__name__)

DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_NAME = os.getenv("DB_NAME")

def get_conn():
    return pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME, connect_timeout=5)

@app.route("/")
def index():
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute("CREATE TABLE IF NOT EXISTS hello (id INT PRIMARY KEY, msg VARCHAR(100))")
            cur.execute("INSERT IGNORE INTO hello (id, msg) VALUES (1, 'Hello from ASG via RDS!')")
            cur.execute("SELECT id, msg FROM hello ORDER BY id LIMIT 5")
            rows = cur.fetchall()
        conn.commit()
        conn.close()
        rows_html = "<br>".join([f"{r[0]}: {r[1]}" for r in rows])
        return f"<h1>OK: ALB → Web (ASG) → RDS</h1><p>{rows_html}</p>"
    except Exception as e:
        return f"<h1>Error</h1><pre>{e}</pre>", 500
PY

    # Env file (double-dollar to avoid Terraform interpolation)
    cat >/opt/app/app.env <<ENV
DB_HOST=$${DB_HOST}
DB_USER=$${DB_USER}
DB_PASS=$${DB_PASS}
DB_NAME=$${DB_NAME}
PYTHONUNBUFFERED=1
ENV
    chmod 600 /opt/app/app.env

    # Gunicorn service
    cat >/etc/systemd/system/app.service <<'UNIT'
[Unit]
Description=Flask app (Gunicorn)
After=network.target

[Service]
EnvironmentFile=/opt/app/app.env
WorkingDirectory=/opt/app
ExecStart=/usr/local/bin/gunicorn --bind 127.0.0.1:5000 app:app
Restart=always
User=root

[Install]
WantedBy=multi-user.target
UNIT

    # Nginx reverse proxy
    cat >/etc/nginx/conf.d/flask.conf <<'NGX'
server {
    listen 80 default_server;
    server_name _;
    location / {
        proxy_pass         http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header   Host $$host;
        proxy_set_header   X-Real-IP $$remote_addr;
        proxy_set_header   X-Forwarded-For $$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $$scheme;
    }
}
NGX

    rm -f /usr/share/nginx/html/index.html || true

    # CloudWatch Agent
    mkdir -p /opt/aws/amazon-cloudwatch-agent/etc
    cat >/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json <<'JSON'
{
  "agent": { "metrics_collection_interval": 60, "logfile": "/opt/aws/amazon-cloudwatch-agent/logs/agent.log" },
  "metrics": {
    "append_dimensions": { "AutoScalingGroupName": "$${aws:AutoScalingGroupName}" },
    "metrics_collected": {
      "cpu": { "resources": ["*"], "measurement": ["cpu_usage_idle","cpu_usage_user","cpu_usage_system"], "totalcpu": true },
      "mem": { "measurement": ["mem_used_percent"] }
    }
  },
  "logs": {
    "logs_collected": { "files": { "collect_list": [
      { "file_path": "/var/log/messages",         "log_group_name": "/vpc-foundation/web", "log_stream_name": "{instance_id}-messages" },
      { "file_path": "/var/log/nginx/access.log", "log_group_name": "/vpc-foundation/web", "log_stream_name": "{instance_id}-nginx-access" },
      { "file_path": "/var/log/nginx/error.log",  "log_group_name": "/vpc-foundation/web", "log_stream_name": "{instance_id}-nginx-error" }
    ]}}
  }
}
JSON
    dnf -y install amazon-cloudwatch-agent
    systemctl enable amazon-cloudwatch-agent

    systemctl daemon-reload
    systemctl enable nginx app
    systemctl restart nginx
    systemctl start app
    systemctl start amazon-cloudwatch-agent
  EOT
  )

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name    = "web-asg"
      Project = "vpc-foundation"
      Tier    = "web"
    }
  }
}


resource "aws_autoscaling_group" "web_asg_blue" {
  name                      = "web-asg-blue"
  desired_capacity          = var.web_asg_blue_desired
  min_size                  = var.web_min_size
  max_size                  = var.web_max_size
  health_check_type         = "ELB"
  health_check_grace_period = 120

  vpc_zone_identifier = [
    aws_subnet.private[0].id,
    aws_subnet.private[1].id
  ]

  target_group_arns = [aws_lb_target_group.web_tg_blue.arn]

  launch_template {
    id      = aws_launch_template.web_lt.id
    version = "$Latest"
  }

  lifecycle {
    create_before_destroy = true
  }

  tag {
    key                 = "Name"
    value               = "web-asg-blue"
    propagate_at_launch = true
  }

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
      instance_warmup        = 60
    }
    # optional; you can remove to silence the provider warning:
    # triggers = ["launch_template"]
  }
}

resource "aws_autoscaling_group" "web_asg_green" {
  name                      = "web-asg-green"
  desired_capacity          = var.web_asg_green_desired
  min_size                  = 0
  max_size                  = var.web_max_size
  health_check_type         = "ELB"
  health_check_grace_period = 120

  vpc_zone_identifier = [
    aws_subnet.private[0].id,
    aws_subnet.private[1].id
  ]

  target_group_arns = [aws_lb_target_group.web_tg_green.arn]

  launch_template {
    id      = aws_launch_template.web_lt.id
    version = "$Latest"
  }

  lifecycle {
    create_before_destroy = true
  }

  tag {
    key                 = "Name"
    value               = "web-asg-green"
    propagate_at_launch = true
  }

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
      instance_warmup        = 60
    }
    # optional; you can remove to silence the provider warning:
    # triggers = ["launch_template"]
  }
}

############################################
# RDS Secrets + Instance (private)
############################################
resource "random_password" "db_password" {
  length      = 20
  special     = true
  min_upper   = 1
  min_lower   = 1
  min_numeric = 1
  min_special = 1
  # exclude '/', '@', '"', and space
  override_special = "!#$%^&*()-_=+[]{}:,.?~"
}

resource "aws_secretsmanager_secret" "db_secret" {
  name_prefix = "vpc-foundation-db-credentials"
}

resource "aws_secretsmanager_secret_version" "db_secret_v" {
  secret_id = aws_secretsmanager_secret.db_secret.id
  secret_string = jsonencode({
    username = var.db_username
    password = random_password.db_password.result
    engine   = var.db_engine
    dbname   = var.db_name
  })
}

resource "aws_db_subnet_group" "db_subnets" {
  name       = "db-subnet-group"
  subnet_ids = [aws_subnet.private[0].id, aws_subnet.private[1].id]
  tags       = { Name = "db-subnet-group" }
}

resource "aws_security_group" "db_sg" {
  name        = "db-sg"
  vpc_id      = aws_vpc.this.id
  description = "Allow MySQL only from app/private & web tiers; optional bastion"

  # MySQL from private app servers
  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.private_sg.id]
    description     = "MySQL from private app tier"
  }

  # MySQL from web tier (ASG instances)
  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.web_sg.id]
    description     = "MySQL from web tier"
  }

  # Optional: toggle to allow bastion for initial testing
  dynamic "ingress" {
    for_each = var.allow_bastion_db_access ? [1] : []
    content {
      from_port       = 3306
      to_port         = 3306
      protocol        = "tcp"
      security_groups = [aws_security_group.public_sg.id]
      description     = "TEMP: MySQL from bastion"
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "db-sg" }
}

resource "aws_db_instance" "mysql" {
  identifier     = "vpc-foundation-mysql"
  engine         = var.db_engine
  engine_version = var.db_engine_version
  instance_class = var.db_instance_class

  allocated_storage = var.db_allocated_gb
  storage_type      = "gp3"

  db_subnet_group_name   = aws_db_subnet_group.db_subnets.name
  vpc_security_group_ids = [aws_security_group.db_sg.id]
  multi_az               = var.db_multi_az
  publicly_accessible    = false

  db_name  = var.db_name
  username = var.db_username
  password = random_password.db_password.result

  backup_retention_period = 1
  deletion_protection     = false
  skip_final_snapshot     = true
  apply_immediately       = true

  tags = {
    Name    = "vpc-foundation-mysql"
    Project = "vpc-foundation"
    Tier    = "db"
  }
}

############################################
# Alerts / Budgets / Security Services (optional)
############################################
resource "aws_sns_topic" "alerts" {
  name = "vpc-foundation-alerts"
  tags = { Project = "vpc-foundation" }
}

resource "aws_sns_topic_subscription" "alerts_email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# CPU alarm for BLUE ASG
resource "aws_cloudwatch_metric_alarm" "asg_cpu_high_blue" {
  count               = var.enable_asg_alarms ? 1 : 0
  alarm_name          = "ASG-CPU-High-BLUE"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  threshold           = 70
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  dimensions          = { AutoScalingGroupName = aws_autoscaling_group.web_asg_blue.name }
  alarm_description   = "ASG BLUE average CPU > 70% over 2 minutes"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

# CPU alarm for GREEN ASG (only if we’re actually running any)
resource "aws_cloudwatch_metric_alarm" "asg_cpu_high_green" {
  count               = var.enable_asg_alarms && var.web_asg_green_desired > 0 ? 1 : 0
  alarm_name          = "ASG-CPU-High-GREEN"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  threshold           = 70
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  dimensions          = { AutoScalingGroupName = aws_autoscaling_group.web_asg_green.name }
  alarm_description   = "ASG GREEN average CPU > 70% over 2 minutes"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

# ALB HTTP 5xx > 5 per minute
resource "aws_cloudwatch_metric_alarm" "alb_5xx" {
  alarm_name          = "ALB-HTTP-5XX-High"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  threshold           = 5
  metric_name         = "HTTPCode_ELB_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  dimensions          = { LoadBalancer = aws_lb.web_alb.arn_suffix }
  alarm_description   = "ALB 5xx errors > 5 in the last minute"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}
# Who writes ALB logs
data "aws_elb_service_account" "this" {}

# Random suffix so bucket name is globally unique
resource "random_id" "prefix" {
  byte_length = 4
}

# S3 bucket for ALB logs
resource "aws_s3_bucket" "alb_logs" {
  bucket        = "alb-logs-${var.aws_region}-${random_id.prefix.hex}"
  force_destroy = true
  tags = {
    Project = "vpc-foundation"
  }
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket                  = aws_s3_bucket.alb_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "ELBWrite",
        Effect    = "Allow",
        Principal = { AWS = data.aws_elb_service_account.this.arn },
        Action    = "s3:PutObject",
        Resource  = "${aws_s3_bucket.alb_logs.arn}/*",
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      }
    ]
  })
}

############################################
# CloudTrail -> S3 with lifecycle
############################################

# Random suffix so the S3 bucket name is globally unique

# S3 bucket for CloudTrail logs
resource "aws_s3_bucket" "trail" {
  bucket        = "trail-logs-${var.aws_region}-${random_id.prefix.hex}"
  force_destroy = true

  tags = {
    Name    = "cloudtrail-logs"
    Project = "vpc-foundation"
  }
}

# Strong public access blocks
resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Server-side encryption (SSE-S3)
resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Lifecycle to expire logs after N days
resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    id     = "expire"
    status = "Enabled"

    # Apply to all objects in the bucket
    filter {
      prefix = ""
    }

    expiration {
      days = var.trail_bucket_days
    }
  }
}

# Needed to build the policy path to AWSLogs/<account-id>/*
data "aws_caller_identity" "me" {}

# Bucket policy: allow CloudTrail to write
data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
  }

  # If your bucket has ACLs enabled (default), CloudTrail requires the ACL condition.
  # If you later switch the bucket to "Object Ownership: Bucket owner enforced (ACLs disabled)",
  # remove the Condition block below.
  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_caller_identity.me.account_id}/*"
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket.json
}

# The CloudTrail itself
resource "aws_cloudtrail" "this" {
  name                          = "vpc-foundation-trail"
  s3_bucket_name                = aws_s3_bucket.trail.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  # Make sure the bucket policy exists before the trail tries to write
  depends_on = [aws_s3_bucket_policy.trail]
}


# GuardDuty (optional)
resource "aws_guardduty_detector" "this" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true
  tags   = { Project = "vpc-foundation" }
}
