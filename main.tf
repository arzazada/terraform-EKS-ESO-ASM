

###########    EKS    ########

module "EKS" {
  source       = "./modules/EKS"
  cluster_name = "eso-cluster"
  vpc_cidr     = "10.0.0.0/16"
  az_count     = 2
  public_api   = true
  env          = "dev"
}
########### ESO_ASM    ########

module "ESO_ASM" {
  source            = "./modules/ESO_ASM"
  env               = "dev"
  eso               = true
  eso_chart_version = "0.9.8"
  oidc_provider_sts = module.EKS.oidc_provider_sts
}

