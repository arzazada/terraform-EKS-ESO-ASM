# https://external-secrets.io/latest/introduction/getting-started/#installing-with-helm
# https://github.com/external-secrets/external-secrets/tree/main/deploy/charts/external-secrets


# https://external-secrets.io/latest/provider/aws-secrets-manager/
# https://external-secrets.io/latest/api/clustersecretstore/#example
# https://external-secrets.io/latest/api/clustersecretstore/
# https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html
/*

To manually update secrets from source:
kubectl annotate es my-es force-sync=$(date +%s) --overwrite

*/

resource "kubernetes_namespace" "external_secrets" {
  count = var.eso ? 1 : 0
  metadata {
    name   = "external-secrets"
    labels = local.default_labels
  }

  lifecycle {
    ignore_changes = [
      metadata[0].annotations,
      metadata[0].labels
    ]
  }
}

resource "helm_release" "external_secrets" {

  #  depends_on = [asm}

  count      = var.eso ? 1 : 0
  name       = "external-secrets"
  namespace  = "external-secrets"
  repository = "https://charts.external-secrets.io"
  chart      = "external-secrets"
  version    = var.eso_chart_version

  create_namespace = false

  set {
    name  = "installCRDs"
    value = "true"
  }

  set {
    name  = "webhook.port"
    value = "9443"
  }

}


resource "kubernetes_service_account" "cluster_secret_store" {
  count = var.eso ? 1 : 0

  metadata {
    name      = "eso-cluster-css-sa"
    namespace = kubernetes_namespace.external_secrets[0].metadata[0].name
    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.secrets_manager_role.arn
    }
  }
}

resource "kubernetes_manifest" "secrets_manager_secret_store" {
  count = var.eso ? 1 : 0

  depends_on = [helm_release.external_secrets]
  manifest = {
    apiVersion = "external-secrets.io/v1beta1"
    kind       = "ClusterSecretStore"
    metadata = {
      name = "acm-css"
    }
    spec = {
      provider = {
        aws = {
          service = "SecretsManager"
          region  = local.region
          auth = {
            jwt = {
              serviceAccountRef = {
                name      = kubernetes_service_account.cluster_secret_store[0].metadata[0].name
                namespace = kubernetes_namespace.external_secrets[0].metadata[0].name
              }
            }
          }
        }
      }
      conditions = [
        {
          namespaceSelector = {
            matchLabels = {
              "kubernetes.io/environment" = var.env
            }
          }
        }
      ]
    }
  }
}

data "aws_iam_policy_document" "secrets_manager_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(var.oidc_provider_sts.url, "https://", "")}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${replace(var.oidc_provider_sts.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:external-secrets:eso-cluster-css-sa"]
    }

    principals {
      identifiers = [var.oidc_provider_sts.arn]
      type        = "Federated"
    }
  }
}


resource "aws_iam_role" "secrets_manager_role" {
  name               = "secretsManagerRole"
  assume_role_policy = data.aws_iam_policy_document.secrets_manager_assume_role_policy.json
}


resource "aws_iam_policy" "secrets_manager_policy" {
  name = "secrets_manager_policy"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [{
      "Effect" : "Allow",
      "Action" : [
        "secretsmanager:GetResourcePolicy",
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret",
        "secretsmanager:ListSecretVersionIds"
      ],
      "Resource" : [
        "arn:aws:secretsmanager:${local.region}:${local.account_id}:secret:*"
      ]
    }]
  })
}

resource "aws_iam_role_policy_attachment" "secrets_manager_policy_attachment" {
  role       = aws_iam_role.secrets_manager_role.name
  policy_arn = aws_iam_policy.secrets_manager_policy.arn
}



