resource "aws_ecs_cluster" "jula" {
  name = "jula-cluster"
}

resource "aws_cloudwatch_log_group" "jula" {
  name              = "/ecs/jula"
  retention_in_days = 7
}

# Dedicated Security Group for tasks that blocks all ingress and allows all egress
resource "aws_security_group" "ecs_tasks" {
  name        = "jula-ecs-tasks-sg"
  description = "Allows outbound traffic for Jula ECS Fargate tasks"
  vpc_id      = local.target_vpc_id

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

# Jula Collector Task Definition
resource "aws_ecs_task_definition" "collector" {
  family                   = "jula-collector"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([
    {
      name      = "jula-collector"
      image     = "${aws_ecr_repository.collector.repository_url}:${var.collector_image_tag}"
      essential = true
      command   = ["run"]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.jula.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "collector"
        }
      }

      environment = [
        {
          name  = "JULA_OUTPUT_PATH"
          value = "s3://${aws_s3_bucket.evidence.id}"
        },
        {
          name  = "JULA_SOURCE_ORG"
          value = var.git_org
        },
        {
          name  = "JULA_INTEGRATION_URL"
          value = var.integration_url
        },
        {
          name  = "JULA_SOURCE_TOKEN_ENV"
          value = var.source_token_env_name
        },
        {
          name  = "JULA_ALLOWED_HOSTS"
          value = var.allowed_hosts
        },
        {
          name  = "AWS_DEFAULT_REGION"
          value = var.aws_region
        },
        {
          name  = "JULA_DEPLOYMENT_ID"
          value = random_string.deployment_id.result
        },
        {
          name  = "JULA_PROVIDER"
          value = var.jula_provider
        },
        {
          name  = "JULA_SOURCE_REPO"
          value = "jula"
        }
      ]

      secrets = [
        {
          name      = "JULA_SIGNING_KEY"
          valueFrom = aws_secretsmanager_secret.signing_key.arn
        },
        {
          name      = var.source_token_env_name
          valueFrom = aws_secretsmanager_secret.source_token.arn
        }
      ]
    }
  ])
}

# Jula Assessor Task Definition
resource "aws_ecs_task_definition" "assessor" {
  family                   = "jula-assessor"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([
    {
      name      = "jula-assessor"
      image     = "${aws_ecr_repository.assessor.repository_url}:${var.assessor_image_tag}"
      essential = true
      command   = ["run"]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.jula.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "assessor"
        }
      }

      environment = [
        {
          name  = "JULA_BUCKET_URL"
          value = "s3://${aws_s3_bucket.evidence.id}"
        },
        {
          name  = "JULA_POLICY_URL"
          value = var.policy_url
        },
        {
          name  = "JULA_GOVERNOR_REPO"
          value = var.governor_repo
        },
        {
          name  = "JULA_SOURCE_TOKEN_ENV"
          value = var.source_token_env_name
        },
        {
          name  = "JULA_DEPLOYMENT_ID"
          value = random_string.deployment_id.result
        }
      ]

      secrets = [
        {
          name      = "JULA_PUBLIC_KEY"
          valueFrom = aws_secretsmanager_secret.public_key.arn
        },
        {
          name      = var.source_token_env_name
          valueFrom = aws_secretsmanager_secret.source_token.arn
        },
        {
          name      = "JULA_DISPATCH_TOKEN"
          valueFrom = aws_secretsmanager_secret.dispatch_token.arn
        }
      ]
    }
  ])
}
