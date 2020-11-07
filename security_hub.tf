resource "aws_securityhub_account" "security_hub" {
  count = var.enabled
}
