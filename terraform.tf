terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }

    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }

    helm = {
      source  = "hashicorp/helm"
      version = "= 2.5.1"
    }

  }
  backend "http" {}
}


provider "aws" {
  region     = var.region
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
}


provider "helm" {
  kubernetes {
    host                   = module.EKS.kube-api-endpoint
    token                   = module.EKS.kube-api-token
    cluster_ca_certificate = base64decode(module.EKS.kubeconfig-certificate-authority-data)
  }
}

provider "kubernetes" {
  host                   = module.EKS.kube-api-endpoint
  token                  = module.EKS.kube-api-token
  cluster_ca_certificate = base64decode(module.EKS.kubeconfig-certificate-authority-data)
}
