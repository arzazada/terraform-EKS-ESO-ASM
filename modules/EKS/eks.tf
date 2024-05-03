
# ECS-CLUSTER-ROLE
data "aws_iam_policy_document" "eks-cluster-role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "eks-cluster-role" {
  name               = "eksClusterRole"
  assume_role_policy = data.aws_iam_policy_document.eks-cluster-role.json
}

resource "aws_iam_role_policy_attachment" "eks-cluster-role" {
  role       = aws_iam_role.eks-cluster-role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}


#_____________________________________________________

# EKS-CLUSTER
resource "aws_eks_cluster" "eks-cluster" {
  name                      = var.cluster_name
  role_arn                  = aws_iam_role.eks-cluster-role.arn
  enabled_cluster_log_types = ["api", "audit"]
  version                   = "1.29"

  encryption_config {
    provider {
      key_arn = aws_kms_key.eks-cluster.arn
    }
    resources = ["secrets"]
  }

  vpc_config {
    subnet_ids              = aws_subnet.private_subnet[*].id
    security_group_ids      = aws_security_group.private[*].id
    endpoint_private_access = true
    endpoint_public_access  = var.public_api

  }

  depends_on = [
    aws_iam_role_policy_attachment.eks-cluster-role,
    aws_cloudwatch_log_group.eks-cluster
  ]
}

#_____________________________________________________

resource "aws_cloudwatch_log_group" "eks-cluster" {
  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = 3
}

# addons  https://docs.aws.amazon.com/eks/latest/userguide/eks-add-ons.html

resource "aws_eks_addon" "eks-cluster-kube-proxy" {
  cluster_name  = aws_eks_cluster.eks-cluster.name
  addon_name    = "kube-proxy"
  addon_version = "v1.29.1-eksbuild.2" # https://docs.aws.amazon.com/eks/latest/userguide/managing-kube-proxy.html
}

resource "aws_eks_addon" "core_dns" {
  depends_on = [
    aws_eks_fargate_profile.eks-cluster-fargate-kubesystem
  ]

  cluster_name  = aws_eks_cluster.eks-cluster.name
  addon_name    = "coredns"
  addon_version = "v1.11.1-eksbuild.8" #https://docs.aws.amazon.com/eks/latest/userguide/managing-coredns.html

  configuration_values = jsonencode({    # https://andyhunt.me/til/2021/03/29/coredns-does-not-run-on-aws-fargate-by-default/
      computeType  = "fargate"           #
      replicaCount = 1
    })
}

resource "aws_eks_addon" "eks-cluster-vpc-cni" {
  cluster_name             = aws_eks_cluster.eks-cluster.name
  addon_name               = "vpc-cni"
  addon_version            = "v1.18.0-eksbuild.1" # https://docs.aws.amazon.com/eks/latest/userguide/managing-vpc-cni.html
  service_account_role_arn = aws_iam_role.eks-vpc-cni-role.arn
}

# IAM Role for EKS Addon "vpc-cni" with AWS managed policy

data "tls_certificate" "oidc_web_identity" {
  url = aws_eks_cluster.eks-cluster.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "oidc_provider_sts" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.oidc_web_identity.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.eks-cluster.identity[0].oidc[0].issuer
}

resource "aws_iam_role" "eks-vpc-cni-role" {
  assume_role_policy = data.aws_iam_policy_document.eks-vpc-cni-role.json
  name               = "AmazonEKSVPCCNIRole"
}

resource "aws_iam_role_policy_attachment" "eks-vpc-cni-role" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks-vpc-cni-role.name
}

data "aws_iam_policy_document" "eks-vpc-cni-role" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.oidc_provider_sts.url, "https://", "")}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.oidc_provider_sts.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:kube-system:aws-node"]
    }

    principals {
      identifiers = [aws_iam_openid_connect_provider.oidc_provider_sts.arn]
      type        = "Federated"
    }
  }
}


#####################

# FARGATE PROFILE
resource "aws_eks_fargate_profile" "eks-cluster-fargate" {
  for_each               = local.fargate_profiles
  cluster_name           = aws_eks_cluster.eks-cluster.name
  fargate_profile_name   = "fargate-profile-${each.key}"
  pod_execution_role_arn = aws_iam_role.fargate-pod-execution-role.arn
  subnet_ids             = aws_subnet.private_subnet[*].id
  dynamic "selector" {
    for_each = each.value
    content {
      namespace = selector.value.namespace
      labels    = selector.value.labels
    }
  }
}

resource "aws_eks_fargate_profile" "eks-cluster-fargate-kubesystem" {
  cluster_name           = aws_eks_cluster.eks-cluster.name
  fargate_profile_name   = "fargate-profile-kubesystem"
  pod_execution_role_arn = aws_iam_role.fargate-pod-execution-role.arn
  subnet_ids             = aws_subnet.private_subnet[*].id

  selector {
    namespace = "kube-system"
    labels    = {}
  }
}


# fargate pod execution role
data "aws_iam_policy_document" "fargate-pod-execution-role" {
  statement {
    actions = ["sts:AssumeRole"]

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:eks:${local.region}:${local.account_id}:fargateprofile/${var.cluster_name}/*"]
    }

    principals {
      type        = "Service"
      identifiers = ["eks-fargate-pods.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "fargate-pod-execution-role" {
  name               = "AmazonEKSFargatePodExecutionRole"
  assume_role_policy = data.aws_iam_policy_document.fargate-pod-execution-role.json
}

resource "aws_iam_role_policy_attachment" "fargate-pod-execution-role" {
  role       = aws_iam_role.fargate-pod-execution-role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"
}
