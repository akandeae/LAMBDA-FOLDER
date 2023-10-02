variable "handler" {
    default = "lambda-function.lambda_handler"
}


variable " timeout " {
    type = number
    default = 3
}

variable "memory_size" {
    type = number
    default = 356
}


