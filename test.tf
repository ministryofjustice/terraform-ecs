module "ecs" {
  source        = "./ecs"
  name          = "test"
  vpc_id        = "vpc-01d7a2da8f9f1dfec"
  subnet_ids    = ["subnet-04af8bd9dbbce3310", "subnet-0131824ef5a4ece01", "subnet-01815760b71d6a619"]
  instance_type = "t3.large"
  ec2_capacity_enabled = true
  user_data = base64encode(
    <<-EOF
    #!/bin/bash -x
    exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1
      echo ECS_CLUSTER=test >> /etc/ecs/ecs.config
    EOF
  )
  ingress_rules = {
    "all" = {
      description     = "All"
      from_port       = 0
      to_port         = 0
      protocol        = "-1"
      security_groups = []
      cidr_blocks = [
        "0.0.0.0/0"
      ]
    }
  }
  egress_rules = {
    "all" = {
      description     = "All"
      from_port       = 0
      to_port         = 0
      protocol        = "-1"
      security_groups = []
      cidr_blocks = [
        "0.0.0.0/0"
      ]
    }
  }
}

data "aws_subnets" "shared-public" {
  filter {
    name   = "vpc-id"
    values = ["vpc-01d7a2da8f9f1dfec"]
  }
  tags = {
    Name = "hmpps-development-general-public*"
  }
}

resource "aws_lb" "external" {
  # checkov:skip=CKV_AWS_91
  # checkov:skip=CKV2_AWS_28

  name               = "test-jitbit-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.load_balancer_security_group.id]
  subnets            = data.aws_subnets.shared-public.ids

  enable_deletion_protection = true
  drop_invalid_header_fields = true
}

data "aws_subnet" "private_subnets_a" {
  vpc_id = "vpc-01d7a2da8f9f1dfec"
  tags = {
    "Name" = "hmpps-development-general-private-eu-west-2a"
  }
}

data "aws_subnet" "private_subnets_b" {
  vpc_id = "vpc-01d7a2da8f9f1dfec"
  tags = {
    "Name" = "hmpps-development-general-private-eu-west-2b"

  }
}

data "aws_subnet" "private_subnets_c" {
  vpc_id = "vpc-01d7a2da8f9f1dfec"
  tags = {
    "Name" = "hmpps-development-general-private-eu-west-2c"
  }
}

resource "aws_security_group" "load_balancer_security_group" {
  name_prefix = "test-jibit-loadbalancer-security-group"
  description = "controls access to lb"
  vpc_id      = "vpc-01d7a2da8f9f1dfec"

  ingress {
    protocol    = "tcp"
    description = "Allow ingress from white listed CIDRs"
    from_port   = 80
    to_port     = 80
    cidr_blocks = ["81.134.202.29/32", "82.8.44.191/32"]
  }

  egress {
    protocol    = "tcp"
    description = "Allow egress to ECS instances"
    from_port   = 5000
    to_port     = 5000
    cidr_blocks = [data.aws_subnet.private_subnets_a.cidr_block, data.aws_subnet.private_subnets_b.cidr_block, data.aws_subnet.private_subnets_c.cidr_block]
  }
}

resource "aws_lb_listener" "listener" {
  load_balancer_arn = aws_lb.external.id
  port              = 80
  protocol          = "HTTP"

  default_action {
    target_group_arn = aws_lb_target_group.target_group.id
    type             = "forward"
  }
}

resource "aws_lb_target_group" "target_group" {
  # checkov:skip=CKV_AWS_261

  name                 = "test-jitbit-tg"
  port                 = 5000
  protocol             = "HTTP"
  vpc_id               = "vpc-01d7a2da8f9f1dfec"
  target_type          = "instance"
  deregistration_delay = 30

  stickiness {
    type = "lb_cookie"
  }

  health_check {
    path                = "/User/Login?ReturnUrl=%2f"
    healthy_threshold   = "5"
    interval            = "120"
    protocol            = "HTTP"
    unhealthy_threshold = "2"
    matcher             = "200-499"
    timeout             = "5"
  }
}

provider "aws" {
  region = "eu-west-2"
}
