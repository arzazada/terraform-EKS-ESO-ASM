output "kube-api-endpoint" {
  value = aws_eks_cluster.eks-cluster.endpoint
}

output "kubeconfig-certificate-authority-data" {
  value = aws_eks_cluster.eks-cluster.certificate_authority[0].data
}

data "aws_eks_cluster_auth" "eks" {
  name = aws_eks_cluster.eks-cluster.name
}

output "kube-api-token" {
  value = data.aws_eks_cluster_auth.eks.token
}


output "oidc_provider_sts" {
  value = aws_iam_openid_connect_provider.oidc_provider_sts
}

