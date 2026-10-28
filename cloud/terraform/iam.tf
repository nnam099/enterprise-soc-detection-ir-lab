resource "aws_iam_user" "wazuh_reader" {
  name = "${var.project}-wazuh-reader"

  tags = { Name = "${var.project}-wazuh-reader" }
}

resource "aws_iam_user_policy" "wazuh_reader_s3" {
  name   = "ReadCloudLogs"
  user   = aws_iam_user.wazuh_reader.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ListLogBucket"
        Effect   = "Allow"
        Action   = ["s3:ListBucket", "s3:GetBucketLocation"]
        Resource = [aws_s3_bucket.logs.arn]
      },
      {
        Sid      = "ReadLogObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = ["${aws_s3_bucket.logs.arn}/*"]
      },
      {
        Sid      = "ReadFlowLogMetadata"
        Effect   = "Allow"
        Action   = ["ec2:DescribeFlowLogs", "ec2:DescribeVpcs", "ec2:DescribeSubnets", "ec2:DescribeNetworkInterfaces"]
        Resource = ["*"]
      },
      {
        Sid      = "DecryptGuardDutyFindings"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [aws_kms_key.guardduty.arn]
      }
    ]
  })
}

resource "aws_iam_access_key" "wazuh_reader" {
  user = aws_iam_user.wazuh_reader.name
}
