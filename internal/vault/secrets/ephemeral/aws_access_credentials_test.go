// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAccAWSAccessCredentialsCredIamUser confirms that AWS credentials
// are correctly generated from Vault into the ephemeral resource
// Creates the AWS backend and role,
// then uses the ephemeral resource to generate credentials.
// Uses the Echo Provider to test values set in ephemeral resources
// see documentation here for more details:
// https://developer.hashicorp.com/terraform/plugin/testing/acceptance-tests/ephemeral-resources#using-echo-provider-in-acceptance-tests
// Note: This test will fail on Vault 1.19 with "number of regions does not match number of endpoints" error.
// This is a known Vault bug affecting the AWS secrets engine's Creds endpoint.
// Hence skipping the test for Vault 1.19.

func TestAccAWSAccessCredentialsCredIamUser(t *testing.T) {
	a, s := testutil.GetTestAWSCreds(t)
	region := testutil.GetTestAWSRegion(t)
	mount := acctest.RandomWithPrefix("tf-aws")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionEQ(t, provider.VaultVersion119)
		},
		// Include the provider we want to test
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		// Include `echo` as a v6 provider from `terraform-plugin-testing`
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAWSAccessCredentialsConfigIamUser(mount, a, s, region),
				ConfigStateChecks: []statecheck.StateCheck{
					// Verify that we got the access_key and secret_key set
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("access_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("secret_key"), knownvalue.NotNull()),
					// For creds type, security_token should be empty
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("security_token"), knownvalue.StringExact("")),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("type"), knownvalue.StringExact("creds")),
				},
			},
		},
	})
}

// TestAccAWSAccessCredentialsSTS tests STS token generation
// creates the AWS backend and role,then uses the ephemeral resource to generate STS credentials.
// Note: This test skips on Vault 1.19 with "number of regions does not match number of endpoints" error.
// This is a known Vault bug affecting the AWS secrets engine's STS endpoint.
func TestAccAWSAccessCredentialsSTSFederationToken(t *testing.T) {
	a, s := testutil.GetTestAWSCreds(t)
	region := testutil.GetTestAWSRegion(t)
	ttl := "15m"
	mount := acctest.RandomWithPrefix("tf-aws-sts")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionEQ(t, provider.VaultVersion119)
		},
		// Include the provider we want to test
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		// Include `echo` as a v6 provider from `terraform-plugin-testing`
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAWSAccessCredentialsSTSConfigFederationToken(mount, a, s, region, ttl),
				ConfigStateChecks: []statecheck.StateCheck{
					// Verify that we got the access_key, secret_key, and security_token set
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("access_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("secret_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("security_token"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("type"), knownvalue.StringExact("sts")),
				},
			},
		},
	})
}

func testAWSAccessCredentialsConfigIamUser(mount, access, secret, region string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "aws" {
  path = "%s"
  description = "Obtain AWS credentials."
  access_key = "%s"
  secret_key = "%s"
  region = "%s"
}

resource "vault_aws_secret_backend_role" "role" {
  backend = vault_aws_secret_backend.aws.path
  name = "test"
  credential_type = "iam_user"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "iam:GetUser"
      Resource = "*"
    }]
  })
}

ephemeral "vault_aws_access_credentials" "creds" {
  mount  = vault_aws_secret_backend.aws.path
  role     = vault_aws_secret_backend_role.role.name
  type     = "creds"
  mount_id = vault_aws_secret_backend_role.role.id
}

provider "echo" {
  data = {
    access_key = ephemeral.vault_aws_access_credentials.creds.access_key
    secret_key = ephemeral.vault_aws_access_credentials.creds.secret_key
    security_token = ephemeral.vault_aws_access_credentials.creds.security_token
    type = ephemeral.vault_aws_access_credentials.creds.type
  }
}

resource "echo" "test" {}
`, mount, access, secret, region)
}

func testAWSAccessCredentialsSTSConfigFederationToken(mount, access, secret, region, ttl string) string {
	return fmt.Sprintf(`
resource "vault_aws_secret_backend" "aws" {
  path = "%s"
  description = "Obtain AWS credentials."
  access_key = "%s"
  secret_key = "%s"
  region = "%s"
}

resource "vault_aws_secret_backend_role" "role" {
  backend = vault_aws_secret_backend.aws.path
  name = "test"
  credential_type = "federation_token"
  default_sts_ttl = 900
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "iam:GetUser"
      Resource = "*"
    }]
  })
}

ephemeral "vault_aws_access_credentials" "sts" {
  mount  = vault_aws_secret_backend.aws.path
  role     = vault_aws_secret_backend_role.role.name
  type     = "sts"
  region   = vault_aws_secret_backend.aws.region
  ttl      = "%s"
  mount_id = vault_aws_secret_backend_role.role.id
}

provider "echo" {
  data = {
    access_key = ephemeral.vault_aws_access_credentials.sts.access_key
    secret_key = ephemeral.vault_aws_access_credentials.sts.secret_key
    security_token = ephemeral.vault_aws_access_credentials.sts.security_token
    type = ephemeral.vault_aws_access_credentials.sts.type
  }
}

resource "echo" "test" {}
`, mount, access, secret, region, ttl)
}
