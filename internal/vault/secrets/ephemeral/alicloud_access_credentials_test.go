// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets_test

import (
	"fmt"
	"os"
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
)

// TestAccAliCloudAccessCredentialsEphemeralResource_basic tests the creation of
// AliCloud credentials using ephemeral resource.
//
// This test requires the following environment variables to be set:
//   - ALICLOUD_ACCESS_KEY: AliCloud access key for Vault backend configuration
//   - ALICLOUD_SECRET_KEY: AliCloud secret key for Vault backend configuration
func TestAccAliCloudAccessCredentialsEphemeralResource_basic(t *testing.T) {
	accessKey := os.Getenv("ALICLOUD_ACCESS_KEY")
	secretKey := os.Getenv("ALICLOUD_SECRET_KEY")

	if accessKey == "" || secretKey == "" {
		t.Skip("ALICLOUD_ACCESS_KEY and ALICLOUD_SECRET_KEY must be set for acceptance tests")
	}

	backend := acctest.RandomWithPrefix("tf-alicloud")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				// Step 1: Create backend and role
				Config: testAccAliCloudAccessCredentialsEphemeralResourceConfig_setup(backend, role, accessKey, secretKey),
			},
			{
				// Step 2: Use ephemeral resource
				Config: testAccAliCloudAccessCredentialsEphemeralResourceConfig_basic(backend, role, accessKey, secretKey),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("mount"), knownvalue.StringExact(backend)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("role"), knownvalue.StringExact(role)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("access_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("secret_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("lease_id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("lease_duration"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("lease_start_time"), knownvalue.NotNull()),
				},
			},
		},
	})
}

// TestAccAliCloudAccessCredentialsEphemeralResource_defaultMount tests the creation of
// AliCloud credentials using the default mount path.
func TestAccAliCloudAccessCredentialsEphemeralResource_defaultMount(t *testing.T) {
	accessKey := os.Getenv("ALICLOUD_ACCESS_KEY")
	secretKey := os.Getenv("ALICLOUD_SECRET_KEY")

	if accessKey == "" || secretKey == "" {
		t.Skip("ALICLOUD_ACCESS_KEY and ALICLOUD_SECRET_KEY must be set for acceptance tests")
	}

	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccAliCloudAccessCredentialsEphemeralResourceConfig_defaultMountSetup(role, accessKey, secretKey),
			},
			{
				Config: testAccAliCloudAccessCredentialsEphemeralResourceConfig_defaultMount(role, accessKey, secretKey),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("mount"), knownvalue.StringExact("alicloud")),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("role"), knownvalue.StringExact(role)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("access_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("secret_key"), knownvalue.NotNull()),
				},
			},
		},
	})
}

// TestAccAliCloudAccessCredentialsEphemeralResource_namespace tests the creation of
// AliCloud credentials in a Vault namespace.
func TestAccAliCloudAccessCredentialsEphemeralResource_namespace(t *testing.T) {
	accessKey := os.Getenv("ALICLOUD_ACCESS_KEY")
	secretKey := os.Getenv("ALICLOUD_SECRET_KEY")

	if accessKey == "" || secretKey == "" {
		t.Skip("ALICLOUD_ACCESS_KEY and ALICLOUD_SECRET_KEY must be set for acceptance tests")
	}

	backend := acctest.RandomWithPrefix("tf-alicloud")
	role := acctest.RandomWithPrefix("test-role")
	namespace := acctest.RandomWithPrefix("test-ns")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion110)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccAliCloudAccessCredentialsEphemeralResourceConfig_namespaceSetup(backend, role, namespace, accessKey, secretKey),
			},
			{
				Config: testAccAliCloudAccessCredentialsEphemeralResourceConfig_namespace(backend, role, namespace, accessKey, secretKey),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("mount"), knownvalue.StringExact(backend)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("role"), knownvalue.StringExact(role)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("access_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("secret_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("lease_id"), knownvalue.NotNull()),
				},
			},
		},
	})
}

// TestAccAliCloudAccessCredentialsEphemeralResource_roleARN tests the creation of
// AliCloud credentials using a role ARN (AssumeRole).
func TestAccAliCloudAccessCredentialsEphemeralResource_roleARN(t *testing.T) {
	accessKey := os.Getenv("ALICLOUD_ACCESS_KEY")
	secretKey := os.Getenv("ALICLOUD_SECRET_KEY")
	roleARN := os.Getenv("ALICLOUD_ROLE_ARN")

	if accessKey == "" || secretKey == "" {
		t.Skip("ALICLOUD_ACCESS_KEY and ALICLOUD_SECRET_KEY must be set for acceptance tests")
	}

	if roleARN == "" {
		t.Skip("ALICLOUD_ROLE_ARN must be set for role ARN acceptance tests")
	}

	backend := acctest.RandomWithPrefix("tf-alicloud")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccAliCloudAccessCredentialsEphemeralResourceConfig_roleARNSetup(backend, role, roleARN, accessKey, secretKey),
			},
			{
				Config: testAccAliCloudAccessCredentialsEphemeralResourceConfig_roleARN(backend, role, roleARN, accessKey, secretKey),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("mount"), knownvalue.StringExact(backend)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("role"), knownvalue.StringExact(role)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("access_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("secret_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("security_token"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("expiration"), knownvalue.NotNull()),
				},
			},
		},
	})
}

// TestAccAliCloudAccessCredentialsEphemeralResource_inlinePolicy tests the creation of
// AliCloud credentials using inline policies.
func TestAccAliCloudAccessCredentialsEphemeralResource_inlinePolicy(t *testing.T) {
	accessKey := os.Getenv("ALICLOUD_ACCESS_KEY")
	secretKey := os.Getenv("ALICLOUD_SECRET_KEY")

	if accessKey == "" || secretKey == "" {
		t.Skip("ALICLOUD_ACCESS_KEY and ALICLOUD_SECRET_KEY must be set for acceptance tests")
	}

	backend := acctest.RandomWithPrefix("tf-alicloud")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccAliCloudAccessCredentialsEphemeralResourceConfig_inlinePolicySetup(backend, role, accessKey, secretKey),
			},
			{
				Config: testAccAliCloudAccessCredentialsEphemeralResourceConfig_inlinePolicy(backend, role, accessKey, secretKey),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("mount"), knownvalue.StringExact(backend)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("role"), knownvalue.StringExact(role)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("access_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("secret_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("security_token"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("expiration"), knownvalue.NotNull()),
				},
			},
		},
	})
}

// TestAccAliCloudAccessCredentialsEphemeralResource_remotePolicy tests the creation of
// AliCloud credentials using remote policies.
func TestAccAliCloudAccessCredentialsEphemeralResource_remotePolicy(t *testing.T) {
	accessKey := os.Getenv("ALICLOUD_ACCESS_KEY")
	secretKey := os.Getenv("ALICLOUD_SECRET_KEY")

	if accessKey == "" || secretKey == "" {
		t.Skip("ALICLOUD_ACCESS_KEY and ALICLOUD_SECRET_KEY must be set for acceptance tests")
	}

	backend := acctest.RandomWithPrefix("tf-alicloud")
	role := acctest.RandomWithPrefix("test-role")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccAliCloudAccessCredentialsEphemeralResourceConfig_remotePolicySetup(backend, role, accessKey, secretKey),
			},
			{
				Config: testAccAliCloudAccessCredentialsEphemeralResourceConfig_remotePolicy(backend, role, accessKey, secretKey),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("mount"), knownvalue.StringExact(backend)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("role"), knownvalue.StringExact(role)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("access_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("secret_key"), knownvalue.NotNull()),
				},
			},
		},
	})
}

// Setup functions (Step 1: Create backend and role)
func testAccAliCloudAccessCredentialsEphemeralResourceConfig_setup(backend, role, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_alicloud_secret_backend" "test" {
  path          = "%s"
  access_key    = "%s"
  secret_key_wo = "%s"
}

resource "vault_alicloud_secret_backend_role" "test" {
  mount = vault_alicloud_secret_backend.test.path
  name  = "%s"
  inline_policies = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["ecs:Describe*"]
      Resource = "*"
    }]
    Version = "1"
  })
  ttl     = 3600
  max_ttl = 7200
}
`, backend, accessKey, secretKey, role)
}

// Full config functions (Step 2: Use ephemeral resource)
func testAccAliCloudAccessCredentialsEphemeralResourceConfig_basic(backend, role, accessKey, secretKey string) string {
	return testAccAliCloudAccessCredentialsEphemeralResourceConfig_setup(backend, role, accessKey, secretKey) + fmt.Sprintf(`

ephemeral "vault_alicloud_access_credentials" "creds" {
  mount = vault_alicloud_secret_backend.test.path
  role  = vault_alicloud_secret_backend_role.test.name
}

provider "echo" {
  data = {
    mount            = ephemeral.vault_alicloud_access_credentials.creds.mount
    role             = ephemeral.vault_alicloud_access_credentials.creds.role
    access_key       = ephemeral.vault_alicloud_access_credentials.creds.access_key
    secret_key       = ephemeral.vault_alicloud_access_credentials.creds.secret_key
    security_token   = ephemeral.vault_alicloud_access_credentials.creds.security_token
    expiration       = ephemeral.vault_alicloud_access_credentials.creds.expiration
    lease_id         = ephemeral.vault_alicloud_access_credentials.creds.lease_id
    lease_duration   = ephemeral.vault_alicloud_access_credentials.creds.lease_duration
    lease_start_time = ephemeral.vault_alicloud_access_credentials.creds.lease_start_time
    lease_renewable  = ephemeral.vault_alicloud_access_credentials.creds.lease_renewable
  }
}

resource "echo" "test" {}
`)
}

func testAccAliCloudAccessCredentialsEphemeralResourceConfig_defaultMountSetup(role, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_alicloud_secret_backend" "test" {
  access_key    = "%s"
  secret_key_wo = "%s"
}

resource "vault_alicloud_secret_backend_role" "test" {
  mount = vault_alicloud_secret_backend.test.path
  name  = "%s"
  inline_policies = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["ecs:Describe*"]
      Resource = "*"
    }]
    Version = "1"
  })
  ttl     = 3600
  max_ttl = 7200
}
`, accessKey, secretKey, role)
}

func testAccAliCloudAccessCredentialsEphemeralResourceConfig_defaultMount(role, accessKey, secretKey string) string {
	return testAccAliCloudAccessCredentialsEphemeralResourceConfig_defaultMountSetup(role, accessKey, secretKey) + `

ephemeral "vault_alicloud_access_credentials" "creds" {
  role = vault_alicloud_secret_backend_role.test.name
}

provider "echo" {
  data = {
    mount      = ephemeral.vault_alicloud_access_credentials.creds.mount
    role       = ephemeral.vault_alicloud_access_credentials.creds.role
    access_key = ephemeral.vault_alicloud_access_credentials.creds.access_key
    secret_key = ephemeral.vault_alicloud_access_credentials.creds.secret_key
  }
}

resource "echo" "test" {}
`
}

func testAccAliCloudAccessCredentialsEphemeralResourceConfig_namespaceSetup(backend, role, namespace, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = "%s"
}

resource "vault_alicloud_secret_backend" "test" {
  namespace     = vault_namespace.test.path
  path          = "%s"
  access_key    = "%s"
  secret_key_wo = "%s"
}

resource "vault_alicloud_secret_backend_role" "test" {
  namespace = vault_namespace.test.path
  mount     = vault_alicloud_secret_backend.test.path
  name      = "%s"
  inline_policies = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["ecs:Describe*"]
      Resource = "*"
    }]
    Version = "1"
  })
  ttl     = 3600
  max_ttl = 7200
}
`, namespace, backend, accessKey, secretKey, role)
}

func testAccAliCloudAccessCredentialsEphemeralResourceConfig_namespace(backend, role, namespace, accessKey, secretKey string) string {
	return testAccAliCloudAccessCredentialsEphemeralResourceConfig_namespaceSetup(backend, role, namespace, accessKey, secretKey) + `

ephemeral "vault_alicloud_access_credentials" "creds" {
  namespace = vault_namespace.test.path
  mount     = vault_alicloud_secret_backend.test.path
  role      = vault_alicloud_secret_backend_role.test.name
}

provider "echo" {
  data = {
    mount      = ephemeral.vault_alicloud_access_credentials.creds.mount
    role       = ephemeral.vault_alicloud_access_credentials.creds.role
    access_key = ephemeral.vault_alicloud_access_credentials.creds.access_key
    secret_key = ephemeral.vault_alicloud_access_credentials.creds.secret_key
    lease_id   = ephemeral.vault_alicloud_access_credentials.creds.lease_id
  }
}

resource "echo" "test" {}
`
}

func testAccAliCloudAccessCredentialsEphemeralResourceConfig_roleARNSetup(backend, role, roleARN, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_alicloud_secret_backend" "test" {
  path          = "%s"
  access_key    = "%s"
  secret_key_wo = "%s"
}

resource "vault_alicloud_secret_backend_role" "test" {
  mount    = vault_alicloud_secret_backend.test.path
  name     = "%s"
  role_arn = "%s"
  ttl      = 3600
  max_ttl  = 7200
}
`, backend, accessKey, secretKey, role, roleARN)
}

func testAccAliCloudAccessCredentialsEphemeralResourceConfig_roleARN(backend, role, roleARN, accessKey, secretKey string) string {
	return testAccAliCloudAccessCredentialsEphemeralResourceConfig_roleARNSetup(backend, role, roleARN, accessKey, secretKey) + `

ephemeral "vault_alicloud_access_credentials" "creds" {
  mount = vault_alicloud_secret_backend.test.path
  role  = vault_alicloud_secret_backend_role.test.name
}

provider "echo" {
  data = {
    mount          = ephemeral.vault_alicloud_access_credentials.creds.mount
    role           = ephemeral.vault_alicloud_access_credentials.creds.role
    access_key     = ephemeral.vault_alicloud_access_credentials.creds.access_key
    secret_key     = ephemeral.vault_alicloud_access_credentials.creds.secret_key
    security_token = ephemeral.vault_alicloud_access_credentials.creds.security_token
    expiration     = ephemeral.vault_alicloud_access_credentials.creds.expiration
  }
}

resource "echo" "test" {}
`
}

func testAccAliCloudAccessCredentialsEphemeralResourceConfig_inlinePolicySetup(backend, role, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_alicloud_secret_backend" "test" {
  path          = "%s"
  access_key    = "%s"
  secret_key_wo = "%s"
}

resource "vault_alicloud_secret_backend_role" "test" {
  mount = vault_alicloud_secret_backend.test.path
  name  = "%s"
  inline_policies = jsonencode({
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ecs:Describe*", "ecs:List*"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["oss:Get*", "oss:List*"]
        Resource = "*"
      }
    ]
    Version = "1"
  })
  ttl     = 1800
  max_ttl = 3600
}
`, backend, accessKey, secretKey, role)
}

func testAccAliCloudAccessCredentialsEphemeralResourceConfig_inlinePolicy(backend, role, accessKey, secretKey string) string {
	return testAccAliCloudAccessCredentialsEphemeralResourceConfig_inlinePolicySetup(backend, role, accessKey, secretKey) + `

ephemeral "vault_alicloud_access_credentials" "creds" {
  mount = vault_alicloud_secret_backend.test.path
  role  = vault_alicloud_secret_backend_role.test.name
}

provider "echo" {
  data = {
    mount          = ephemeral.vault_alicloud_access_credentials.creds.mount
    role           = ephemeral.vault_alicloud_access_credentials.creds.role
    access_key     = ephemeral.vault_alicloud_access_credentials.creds.access_key
    secret_key     = ephemeral.vault_alicloud_access_credentials.creds.secret_key
    security_token = ephemeral.vault_alicloud_access_credentials.creds.security_token
    expiration     = ephemeral.vault_alicloud_access_credentials.creds.expiration
  }
}

resource "echo" "test" {}
`
}

func testAccAliCloudAccessCredentialsEphemeralResourceConfig_remotePolicySetup(backend, role, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_alicloud_secret_backend" "test" {
  path          = "%s"
  access_key    = "%s"
  secret_key_wo = "%s"
}

resource "vault_alicloud_secret_backend_role" "test" {
  mount           = vault_alicloud_secret_backend.test.path
  name            = "%s"
  remote_policies = "name:AliyunECSReadOnlyAccess,type:System,name:AliyunOSSReadOnlyAccess,type:System"
  ttl             = 3600
  max_ttl         = 7200
}
`, backend, accessKey, secretKey, role)
}

func testAccAliCloudAccessCredentialsEphemeralResourceConfig_remotePolicy(backend, role, accessKey, secretKey string) string {
	return testAccAliCloudAccessCredentialsEphemeralResourceConfig_remotePolicySetup(backend, role, accessKey, secretKey) + `

ephemeral "vault_alicloud_access_credentials" "creds" {
  mount = vault_alicloud_secret_backend.test.path
  role  = vault_alicloud_secret_backend_role.test.name
}

provider "echo" {
  data = {
    mount      = ephemeral.vault_alicloud_access_credentials.creds.mount
    role       = ephemeral.vault_alicloud_access_credentials.creds.role
    access_key = ephemeral.vault_alicloud_access_credentials.creds.access_key
    secret_key = ephemeral.vault_alicloud_access_credentials.creds.secret_key
  }
}

resource "echo" "test" {}
`
}

// Made with Bob
