// Cloudwatch event rule to detect Guardduty Findings
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  count       = var.enabled
  name        = "guardduty_findings"
  description = "Event rule to capture Guardduty findings"

  event_pattern = <<PATTERN
{
  "source": [
    "aws.guardduty"
  ],
  "detail-type": [
    "GuardDuty Finding"
  ]
}
PATTERN

}

resource "aws_cloudwatch_event_target" "guardduty_findings_target" {
  count     = var.enabled
  rule      = aws_cloudwatch_event_rule.guardduty_findings[count.index].name
  target_id = "guardduty_findings_target"
  arn       = module.lambda_security_report.lambda_arn
}

resource "aws_lambda_permission" "allow_invocation_guardduty_findings" {
  count         = var.enabled
  statement_id  = "AllowExecutionGuarddutyFindings"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_security_report.lambda_arn
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_findings[count.index].arn
}

// Cloudwatch event rule to detect AWS Config security vulnerabilities Findings
resource "aws_cloudwatch_event_rule" "config_findings" {
  count       = var.enabled
  name        = "config_findings"
  description = "Event rule to capture Config findings"

  event_pattern = <<PATTERN
{
  "source": [
    "aws.config"
  ],
  "detail-type": [
    "Config Rules Compliance Change",
    "Config Rules Re-evaluation Status"
  ]
}
PATTERN

}

resource "aws_cloudwatch_event_target" "config_findings_target" {
  count     = var.enabled
  rule      = aws_cloudwatch_event_rule.config_findings[count.index].name
  target_id = "config_findings_target"
  arn       = module.lambda_security_report.lambda_arn
}

resource "aws_lambda_permission" "allow_invocation_config_findings" {
  count         = var.enabled
  statement_id  = "AllowExecutionConfigFindings"
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_security_report.lambda_arn
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.config_findings[count.index].arn
}
