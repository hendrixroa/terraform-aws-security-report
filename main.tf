module "lambda_security_report" {
  source               = "hendrixroa/lambda/aws"
  enabled              = var.enabled
  code_location        = "${path.module}/${var.code_source}"
  filename             = "securityreport.zip"
  lambda_iam_role      = aws_iam_role.main.arn
  lambda_function_name = var.name
  lambda_runtime       = var.runtime
  timeout              = var.timeout
  memory               = var.memory
  layer_arn            = var.lambda_layer_arn

  subnets = var.subnets
  sg_ids  = [ var.security_group ]

  environment_variables = var.environment_variables
}