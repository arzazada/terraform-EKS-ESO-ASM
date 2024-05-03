data "aws_availability_zones" "az" {
  state = "available"
}
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}


locals {
  az_names   = data.aws_availability_zones.az.names
  account_id = data.aws_caller_identity.current.id
  region     = data.aws_region.current.name

  default_tags = {
    Owner       = "Devops"
    Managed-by  = "Terraform"
    Environment = var.env
  }

  fargate_profiles = {

    profile-1 = [
      { namespace = "default",
        labels = {} }
    ],

    profile-2 = [
      { namespace = "external-secrets",
        labels = {} }
    ]
  }

}
