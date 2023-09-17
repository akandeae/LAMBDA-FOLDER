data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "iam_for_lambda" {
  name               = "iam_for_lambda"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

data "archive_file" "lambda" {
  type        = "zip"
  source_file = "var.source_file"
  output_path = "var.output_path"
}

resource "aws_lambda_function" "test_lambda" {
  # If the file is not in the current working directory you will need to include a
  # path.module in the filename.
  filename      = "var.filename"
  function_name = "var.function_name"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "var.handler"

  source_code_hash = data.archive_file.lambda.output_base64sha256

  runtime = "var.runtime"

  environment {
    variables = {
      foo = "bar"
    }
  }
}
