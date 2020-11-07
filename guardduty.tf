resource "aws_guardduty_detector" "detector" {
  count  = var.enabled
  enable = true
}
