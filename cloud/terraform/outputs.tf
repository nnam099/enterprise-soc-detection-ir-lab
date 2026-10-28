output "account_id" {
  description = "AWS account ID"
  value       = local.account_id
}

output "region" {
  description = "AWS region"
  value       = var.region
}

output "vpc_id" {
  description = "Lab VPC ID"
  value       = aws_vpc.soc.id
}

output "ec2_instance_id" {
  description = "Web/App server instance ID"
  value       = aws_instance.web.id
}

output "ec2_public_ip" {
  description = "Web/App server public IP"
  value       = aws_instance.web.public_ip
}

output "log_bucket" {
  description = "S3 bucket name"
  value       = aws_s3_bucket.logs.id
}

output "log_bucket_arn" {
  description = "S3 bucket ARN"
  value       = aws_s3_bucket.logs.arn
}

output "wazuh_reader_iam_user" {
  description = "IAM user name for the Wazuh aws-s3 reader"
  value       = aws_iam_user.wazuh_reader.name
}

output "wazuh_reader_access_key_id" {
  description = "Access key ID for the Wazuh aws-s3 reader"
  value       = aws_iam_access_key.wazuh_reader.id
  sensitive   = true
}

output "wazuh_reader_secret_access_key" {
  description = "Secret access key for the Wazuh aws-s3 reader"
  value       = aws_iam_access_key.wazuh_reader.secret
  sensitive   = true
}
