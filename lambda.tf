
locals {
  file_location = "output/zip-files.zip"
}



data "archive_file" "lambda" {
  type        = "zip"
  source_file = "lambda-function.py"
  output_path = "${local.file_location}"
}

resource "aws_lambda_function" "test_lambda" {
  # If the file is not in the current working directory you will need to include a
  # path.module in the filename.
  filename      = "${local.file_location}"
  function_name = "demo-lambda"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = var.handler
  timeout	= var.timeout
  memory_size	= var.memory_size

  source_code_hash = data.archive_file.lambda.output_base64sha256

  runtime = "python3.8"

  environment {
    variables = {
      foo = "bar"
    }
  }
}
