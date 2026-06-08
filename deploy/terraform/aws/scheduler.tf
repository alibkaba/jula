# Daily Trigger for evidence extraction (runs at 3:00 AM UTC daily)
resource "aws_scheduler_schedule" "collector" {
  name        = "jula-daily-evidence-collection"
  group_name  = "default"
  description = "Daily trigger for Jula Collector"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression = "cron(0 3 * * ? *)"

  target {
    arn      = aws_ecs_cluster.jula.arn
    role_arn = aws_iam_role.scheduler_role.arn

    ecs_parameters {
      task_definition_arn = aws_ecs_task_definition.collector.arn
      launch_type         = "FARGATE"

      network_configuration {
        subnets          = local.target_subnets
        assign_public_ip = true
        security_groups  = [aws_security_group.ecs_tasks.id]
      }
    }
  }
}

# Daily Trigger for compliance policy evaluation (runs at 3:30 AM UTC daily)
resource "aws_scheduler_schedule" "evaluator" {
  name        = "jula-daily-evidence-evaluation"
  group_name  = "default"
  description = "Daily trigger for Jula Evaluator"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression = "cron(30 3 * * ? *)"

  target {
    arn      = aws_ecs_cluster.jula.arn
    role_arn = aws_iam_role.scheduler_role.arn

    ecs_parameters {
      task_definition_arn = aws_ecs_task_definition.evaluator.arn
      launch_type         = "FARGATE"

      network_configuration {
        subnets          = local.target_subnets
        assign_public_ip = true
        security_groups  = [aws_security_group.ecs_tasks.id]
      }
    }
  }
}
