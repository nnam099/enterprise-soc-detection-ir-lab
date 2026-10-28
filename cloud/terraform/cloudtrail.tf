resource "aws_cloudtrail" "main" {
  name                          = "${var.project}-trail"
  s3_bucket_name                = aws_s3_bucket.logs.id
  enable_log_file_validation    = true
  is_multi_region_trail         = true
  include_global_service_events = true

  depends_on = [aws_s3_bucket_policy.logs]

  tags = { Name = "${var.project}-trail" }
}
