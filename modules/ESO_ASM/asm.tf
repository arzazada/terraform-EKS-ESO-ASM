

resource "aws_secretsmanager_secret" "secret" {
  recovery_window_in_days = 0
  name                    = "eso-secret"
}

resource "aws_secretsmanager_secret_version" "secret" {
  secret_id = aws_secretsmanager_secret.secret.id
  secret_string = jsonencode({
    password = "eso-super-secure-password"
  })
}


resource "kubernetes_namespace" "postgresql" {
  metadata {
    name = "psql"
    labels = merge(local.default_labels, {
      "kubernetes.io/environment" = var.env
    })
  }

  lifecycle {
    ignore_changes = [
      metadata[0].annotations,
      metadata[0].labels
    ]
  }
}

resource "kubernetes_manifest" "project_external_secret" {
  manifest = {
    apiVersion = "external-secrets.io/v1beta1"
    kind       = "ExternalSecret"
    metadata = {
      name      = "psql-es"
      namespace = kubernetes_namespace.postgresql.metadata[0].name
    }
    spec = {
      secretStoreRef = {
        name = kubernetes_manifest.secrets_manager_secret_store[0].manifest.metadata.name
        kind = "ClusterSecretStore"
      }
      refreshInterval = "60s" # is set to 0 to prevent from being automatically updated
      target = {
        name           = "psql-secret"
        creationPolicy = "Owner"
      }
      data = [
        {
          secretKey = "psql-password"
          remoteRef = {
            key = "eso-secret"
            property = "password"
          }
      }]
    }
  }
}
