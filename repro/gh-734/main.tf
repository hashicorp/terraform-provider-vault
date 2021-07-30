terraform {
  required_version = ">= 0.12"
}

provider "vault" {
  version     = "2.12.2"
  max_retries = 5
}

module "approle-module" {
  source       = "./module"
  approle_name = "approle-Name"
  role_id      = "demo"
  policies = [
    "approle-test",
    "aws-1234567890-test_role"
  ]
}
