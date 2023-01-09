locals {
  ingress_http_rules_port = module.this.enabled && var.security_group_enabled && var.http_enabled ? [
    {
      from_port       = var.http_port
      to_port         = var.http_port
      protocol        = "tcp"
      cidr_blocks     = var.http_ingress_cidr_blocks
      prefix_list_ids = var.http_ingress_prefix_list_ids
  }] : []
  ingress_https_rules_port = module.this.enabled && var.security_group_enabled && var.https_enabled ? [
    {
      from_port       = var.https_port
      to_port         = var.https_port
      protocol        = "tcp"
      cidr_blocks     = var.https_ingress_cidr_blocks
      prefix_list_ids = var.http_ingress_prefix_list_ids
  }] : []

  ingress_rules_ports = concat(local.ingress_http_rules_port, local.ingress_https_rules_port)
}

resource "aws_security_group" "default" {
  count       = module.this.enabled && var.security_group_enabled ? 1 : 0
  description = "Controls access to the ALB (HTTP/HTTPS)"
  vpc_id      = var.vpc_id
  name        = module.this.id
  tags        = module.this.tags

  dynamic "ingress" {
    for_each = local.ingress_rules_ports
    content {
      from_port       = ingress.value.from_port
      to_port         = ingress.value.to_port
      protocol        = ingress.value.protocol
      cidr_blocks     = ingress.value.cidr_blocks
      prefix_list_ids = ingress.value.prefix_list_ids
    }
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

module "access_logs" {
  source  = "cloudposse/lb-s3-bucket/aws"
  version = "0.16.0"

  enabled = module.this.enabled && var.access_logs_enabled && var.access_logs_s3_bucket_id == null

  attributes = compact(concat(module.this.attributes, ["alb", "access", "logs"]))

  force_destroy                 = var.alb_access_logs_s3_bucket_force_destroy
  force_destroy_enabled         = var.alb_access_logs_s3_bucket_force_destroy_enabled
  lifecycle_configuration_rules = var.lifecycle_configuration_rules

  # TODO: deprecate these inputs in favor of `lifecycle_configuration_rules`
  lifecycle_rule_enabled             = var.lifecycle_rule_enabled
  enable_glacier_transition          = var.enable_glacier_transition
  expiration_days                    = var.expiration_days
  glacier_transition_days            = var.glacier_transition_days
  noncurrent_version_expiration_days = var.noncurrent_version_expiration_days
  noncurrent_version_transition_days = var.noncurrent_version_transition_days
  standard_transition_days           = var.standard_transition_days

  context = module.this.context
}

module "default_load_balancer_label" {
  source          = "cloudposse/label/null"
  version         = "0.25.0"
  id_length_limit = var.load_balancer_name_max_length
  context         = module.this.context
}

resource "aws_lb" "default" {
  #bridgecrew:skip=BC_AWS_NETWORKING_41 - Skipping Ensure that ALB Drops HTTP Headers
  #bridgecrew:skip=BC_AWS_LOGGING_22 - Skipping Ensure ELBv2 has Access Logging Enabled
  count              = module.this.enabled ? 1 : 0
  name               = var.load_balancer_name == "" ? module.default_load_balancer_label.id : substr(var.load_balancer_name, 0, var.load_balancer_name_max_length)
  tags               = module.this.tags
  internal           = var.internal
  load_balancer_type = "application"

  security_groups = compact(
    concat(var.security_group_ids, [join("", aws_security_group.default.*.id)]),
  )

  subnets                          = var.subnet_ids
  enable_cross_zone_load_balancing = var.cross_zone_load_balancing_enabled
  enable_http2                     = var.http2_enabled
  idle_timeout                     = var.idle_timeout
  ip_address_type                  = var.ip_address_type
  enable_deletion_protection       = var.deletion_protection_enabled
  drop_invalid_header_fields       = var.drop_invalid_header_fields

  access_logs {
    bucket  = var.access_logs_s3_bucket_id
    prefix  = var.access_logs_prefix
    enabled = var.access_logs_enabled
  }
}

module "default_target_group_label" {
  source          = "cloudposse/label/null"
  version         = "0.25.0"
  attributes      = concat(module.this.attributes, ["default"])
  id_length_limit = var.target_group_name_max_length
  context         = module.this.context
}

resource "aws_lb_target_group" "default" {
  count                = module.this.enabled && var.default_target_group_enabled ? 1 : 0
  name                 = var.target_group_name == "" ? module.default_target_group_label.id : substr(var.target_group_name, 0, var.target_group_name_max_length)
  port                 = var.target_group_port
  protocol             = var.target_group_protocol
  vpc_id               = var.vpc_id
  target_type          = var.target_group_target_type
  deregistration_delay = var.deregistration_delay

  health_check {
    protocol            = var.health_check_protocol != null ? var.health_check_protocol : var.target_group_protocol
    path                = var.health_check_path
    port                = var.health_check_port
    timeout             = var.health_check_timeout
    healthy_threshold   = var.health_check_healthy_threshold
    unhealthy_threshold = var.health_check_unhealthy_threshold
    interval            = var.health_check_interval
    matcher             = var.health_check_matcher
  }

  dynamic "stickiness" {
    for_each = var.stickiness == null ? [] : [var.stickiness]
    content {
      type            = "lb_cookie"
      cookie_duration = stickiness.value.cookie_duration
      enabled         = var.target_group_protocol == "TCP" ? false : stickiness.value.enabled
    }
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(
    module.default_target_group_label.tags,
    var.target_group_additional_tags
  )
}

resource "aws_lb_listener" "http_forward" {
  #bridgecrew:skip=BC_AWS_GENERAL_43 - Skipping Ensure that load balancer is using TLS 1.2.
  #bridgecrew:skip=BC_AWS_NETWORKING_29 - Skipping Ensure ALB Protocol is HTTPS
  count             = module.this.enabled && var.http_enabled && var.http_redirect != true ? 1 : 0
  load_balancer_arn = join("", aws_lb.default.*.arn)
  port              = var.http_port
  protocol          = "HTTP"
  tags              = merge(module.this.tags, var.listener_additional_tags)

  default_action {
    target_group_arn = var.listener_http_fixed_response != null ? null : join("", aws_lb_target_group.default.*.arn)
    type             = var.listener_http_fixed_response != null ? "fixed-response" : "forward"

    dynamic "fixed_response" {
      for_each = var.listener_http_fixed_response != null ? [var.listener_http_fixed_response] : []
      content {
        content_type = fixed_response.value["content_type"]
        message_body = fixed_response.value["message_body"]
        status_code  = fixed_response.value["status_code"]
      }
    }
  }
}

resource "aws_lb_listener" "http_redirect" {
  count             = module.this.enabled && var.http_enabled && var.http_redirect == true ? 1 : 0
  load_balancer_arn = join("", aws_lb.default.*.arn)
  port              = var.http_port
  protocol          = "HTTP"
  tags              = merge(module.this.tags, var.listener_additional_tags)

  default_action {
    target_group_arn = join("", aws_lb_target_group.default.*.arn)
    type             = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  #bridgecrew:skip=BC_AWS_GENERAL_43 - Skipping Ensure that load balancer is using TLS 1.2.
  count             = module.this.enabled && var.https_enabled ? 1 : 0
  load_balancer_arn = join("", aws_lb.default.*.arn)

  port            = var.https_port
  protocol        = "HTTPS"
  ssl_policy      = var.https_ssl_policy
  certificate_arn = var.certificate_arn
  tags            = merge(module.this.tags, var.listener_additional_tags)

  default_action {
    target_group_arn = var.listener_https_fixed_response != null ? null : join("", aws_lb_target_group.default.*.arn)
    type             = var.listener_https_fixed_response != null ? "fixed-response" : "forward"

    dynamic "fixed_response" {
      for_each = var.listener_https_fixed_response != null ? [var.listener_https_fixed_response] : []
      content {
        content_type = fixed_response.value["content_type"]
        message_body = fixed_response.value["message_body"]
        status_code  = fixed_response.value["status_code"]
      }
    }
  }
}

resource "aws_lb_listener_certificate" "https_sni" {
  count           = module.this.enabled && var.https_enabled && var.additional_certs != [] ? length(var.additional_certs) : 0
  listener_arn    = join("", aws_lb_listener.https.*.arn)
  certificate_arn = var.additional_certs[count.index]
}
