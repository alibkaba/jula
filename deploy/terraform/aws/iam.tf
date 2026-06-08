# 1. ECS Task Execution Role (Pulling images, writing logs, resolving secrets)
resource "aws_iam_role" "ecs_execution_role" {
  name = "jula-ecs-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution_standard" {
  role       = aws_iam_role.ecs_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Custom secrets access for ECS execution role to resolve env vars from Secrets Manager
resource "aws_iam_policy" "ecs_execution_secrets" {
  name        = "jula-ecs-execution-secrets"
  description = "Allows ECS agent to resolve Secrets Manager variables for Task Definition"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          aws_secretsmanager_secret.signing_key.arn,
          aws_secretsmanager_secret.public_key.arn,
          aws_secretsmanager_secret.source_token.arn,
          aws_secretsmanager_secret.dispatch_token.arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution_secrets_attach" {
  role       = aws_iam_role.ecs_execution_role.name
  policy_arn = aws_iam_policy.ecs_execution_secrets.arn
}

# 2. ECS Task Role (Runtime environment access)
resource "aws_iam_role" "ecs_task_role" {
  name = "jula-ecs-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

# Grant SecurityAudit permissions to allow the collector to read metadata of AWS configurations
resource "aws_iam_role_policy_attachment" "ecs_task_security_audit" {
  role       = aws_iam_role.ecs_task_role.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# Custom policy to allow reading and writing evidence to Jula S3 bucket
resource "aws_iam_policy" "ecs_task_s3" {
  name        = "jula-ecs-task-s3"
  description = "Allows Jula tasks to deliver and read evidence in the S3 bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:DeleteObject"
        ]
        Resource = [
          aws_s3_bucket.evidence.arn,
          "${aws_s3_bucket.evidence.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_s3_attach" {
  role       = aws_iam_role.ecs_task_role.name
  policy_arn = aws_iam_policy.ecs_task_s3.arn
}

# 3. EventBridge Scheduler Role (Triggering Fargate Tasks)
resource "aws_iam_role" "scheduler_role" {
  name = "jula-scheduler-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "scheduler.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "scheduler_ecs" {
  name        = "jula-scheduler-ecs"
  description = "Allows EventBridge Scheduler to run ECS Fargate tasks"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecs:RunTask"
        ]
        Resource = [
          "*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "iam:PassRole"
        ]
        Resource = [
          aws_iam_role.ecs_execution_role.arn,
          aws_iam_role.ecs_task_role.arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "scheduler_ecs_attach" {
  role       = aws_iam_role.scheduler_role.name
  policy_arn = aws_iam_policy.scheduler_ecs.arn
}
