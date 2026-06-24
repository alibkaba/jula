# Daily Trigger for evidence extraction (runs at 2:00 AM UTC daily)
resource "aws_scheduler_schedule" "collector" {
  name        = "jula-daily-evidence-collection"
  group_name  = "default"
  description = "Daily trigger for Jula Collector"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression = "cron(0 2 * * ? *)"

  target {
    arn      = aws_ecs_cluster.jula.arn
    role_arn = aws_iam_role.scheduler_role.arn

    ecs_parameters {
      task_definition_arn = aws_ecs_task_definition.collector.arn
      launch_type         = "FARGATE"

      network_configuration {
        subnets          = local.private_subnets
        assign_public_ip = false
        security_groups  = [aws_security_group.vpc_endpoints.id]
      }
    }
  }
}

# Daily Trigger for compliance policy evaluation (runs at 2:30 AM UTC daily)
resource "aws_scheduler_schedule" "assessor" {
  name        = "jula-daily-evidence-assessment"
  group_name  = "default"
  description = "Daily trigger for Jula Assessor"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression = "cron(30 2 * * ? *)"

  target {
    arn      = aws_ecs_cluster.jula.arn
    role_arn = aws_iam_role.scheduler_role.arn

    ecs_parameters {
      task_definition_arn = aws_ecs_task_definition.assessor.arn
      launch_type         = "FARGATE"

      network_configuration {
        subnets          = local.private_subnets
        assign_public_ip = false
        security_groups  = [aws_security_group.vpc_endpoints.id]
      }
    }
  }
}
