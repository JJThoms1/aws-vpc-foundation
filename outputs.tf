output "vpc_id" { value = aws_vpc.this.id }
output "public_subnets" { value = aws_subnet.public[*].id }
output "private_subnets" { value = aws_subnet.private[*].id }

# Bastion (optional)
output "bastion_public_ip" {
  value       = var.create_bastion ? aws_instance.bastion[0].public_ip : null
  description = "Bastion public IP (if created)"
}

# ALB + Target Group
output "alb_dns_name" {
  value       = aws_lb.web_alb.dns_name
  description = "Public DNS of the ALB"
}

output "db_endpoint" {
  value       = aws_db_instance.mysql.address
  description = "RDS endpoint (hostname)"
}

output "db_secret_arn" {
  value       = aws_secretsmanager_secret.db_secret.arn
  description = "Secrets Manager ARN for DB credentials"
}

output "alerts_topic_arn" { value = aws_sns_topic.alerts.arn }
output "guardduty_enabled" { value = var.enable_guardduty }

output "alb_logs_bucket" {
  value       = aws_s3_bucket.alb_logs.bucket
  description = "S3 bucket used to store ALB access logs"
}

output "tg_blue" { value = aws_lb_target_group.web_tg_blue.arn }
output "tg_green" { value = aws_lb_target_group.web_tg_green.arn }

output "cloudtrail_bucket" { value = aws_s3_bucket.trail.bucket }
