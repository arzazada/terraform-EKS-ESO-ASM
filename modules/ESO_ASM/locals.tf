data "aws_region" "current" {}
data "aws_caller_identity" "current" {}


locals {
  account_id = data.aws_caller_identity.current.id
  region     = data.aws_region.current.name

  default_labels = {
    "kubernetes.io/environment" = var.env
    "kubernetes.io/owner"       = "Devops"
    "kubernetes.io/managed-by"  = "Terraform"
  }
}