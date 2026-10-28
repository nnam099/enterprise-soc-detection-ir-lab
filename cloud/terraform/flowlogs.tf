resource "aws_flow_log" "vpc" {
  log_destination_type = "s3"
  log_destination      = aws_s3_bucket.logs.arn
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.soc.id

  depends_on = [aws_s3_bucket_policy.logs]

  tags = { Name = "${var.project}-vpc-flowlog" }
}
