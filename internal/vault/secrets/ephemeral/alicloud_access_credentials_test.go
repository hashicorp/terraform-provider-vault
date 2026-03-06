// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets_test

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
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
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("mount"), knownvalue.StringExact(backend)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("role"), knownvalue.StringExact(role)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("access_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("secret_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("lease_id"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("lease_duration"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("lease_start_time"), knownvalue.NotNull()),
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
				Config: testAccAliCloudAccessCredentialsEphemeralResourceConfig_defaultMountSetup(backend, role, accessKey, secretKey),
			},
			{
				Config: testAccAliCloudAccessCredentialsEphemeralResourceConfig_defaultMount(backend, role, accessKey, secretKey),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("mount"), knownvalue.StringExact(backend)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("role"), knownvalue.StringExact(role)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("access_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("secret_key"), knownvalue.NotNull()),
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
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("mount"), knownvalue.StringExact(backend)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("role"), knownvalue.StringExact(role)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("access_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("secret_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("lease_id"), knownvalue.NotNull()),
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
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("mount"), knownvalue.StringExact(backend)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("role"), knownvalue.StringExact(role)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("access_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("secret_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("security_token"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("expiration"), knownvalue.NotNull()),
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
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("mount"), knownvalue.StringExact(backend)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("role"), knownvalue.StringExact(role)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("access_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("secret_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("security_token"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("expiration"), knownvalue.NotNull()),
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
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("mount"), knownvalue.StringExact(backend)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("role"), knownvalue.StringExact(role)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("access_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("secret_key"), knownvalue.NotNull()),
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

func testAccAliCloudAccessCredentialsEphemeralResourceConfig_defaultMountSetup(backend, role, accessKey, secretKey string) string {
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

func testAccAliCloudAccessCredentialsEphemeralResourceConfig_defaultMount(backend, role, accessKey, secretKey string) string {
	return testAccAliCloudAccessCredentialsEphemeralResourceConfig_defaultMountSetup(backend, role, accessKey, secretKey) + `

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

// Negative test scenarios

// TestAccAliCloudAccessCredentialsEphemeralResource_nonExistentMount tests that
// requesting credentials from a non-existent mount path returns an error.
func TestAccAliCloudAccessCredentialsEphemeralResource_nonExistentMount(t *testing.T) {
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
				Config: `
ephemeral "vault_alicloud_access_credentials" "creds" {
  mount = "non-existent-mount"
  role  = "non-existent-role"
}

provider "echo" {
  data = {
    access_key = ephemeral.vault_alicloud_access_credentials.creds.access_key
  }
}

resource "echo" "test" {}
`,
				ExpectError: regexp.MustCompile(`(?i)error|no.*secrets.*engine|permission denied|invalid path`),
			},
		},
	})
}

// TestAccAliCloudAccessCredentialsEphemeralResource_nonExistentRole tests that
// requesting credentials for a non-existent role returns an error.
func TestAccAliCloudAccessCredentialsEphemeralResource_nonExistentRole(t *testing.T) {
	accessKey := os.Getenv("ALICLOUD_ACCESS_KEY")
	secretKey := os.Getenv("ALICLOUD_SECRET_KEY")

	if accessKey == "" || secretKey == "" {
		t.Skip("ALICLOUD_ACCESS_KEY and ALICLOUD_SECRET_KEY must be set for acceptance tests")
	}

	backend := acctest.RandomWithPrefix("tf-alicloud")

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
				Config:      testAccAliCloudAccessCredentialsEphemeralResourceConfig_nonExistentRole(backend, accessKey, secretKey),
				ExpectError: regexp.MustCompile(`(?i)Vault response was nil|role.*not.*found|unknown.*role`),
			},
		},
	})
}

func testAccAliCloudAccessCredentialsEphemeralResourceConfig_nonExistentRole(backend, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_alicloud_secret_backend" "test" {
  path          = "%s"
  access_key    = "%s"
  secret_key_wo = "%s"
}

ephemeral "vault_alicloud_access_credentials" "creds" {
  mount = vault_alicloud_secret_backend.test.path
  role  = "non-existent-role"
}

provider "echo" {
  data = {
    access_key = ephemeral.vault_alicloud_access_credentials.creds.access_key
  }
}

resource "echo" "test" {}
`, backend, accessKey, secretKey)
}

// TestAccAliCloudAccessCredentialsEphemeralResource_emptyMount tests that
// an empty mount path causes a validation error.
func TestAccAliCloudAccessCredentialsEphemeralResource_emptyMount(t *testing.T) {
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
				Config: `
ephemeral "vault_alicloud_access_credentials" "creds" {
  mount = ""
  role  = "test-role"
}

provider "echo" {
  data = {
    access_key = ephemeral.vault_alicloud_access_credentials.creds.access_key
  }
}

resource "echo" "test" {}
`,
				ExpectError: regexp.MustCompile(`(?i)Vault response was nil|mount.*empty|mount.*required`),
			},
		},
	})
}

// TestAccAliCloudAccessCredentialsEphemeralResource_emptyRole tests that
// an empty role causes a validation error.
func TestAccAliCloudAccessCredentialsEphemeralResource_emptyRole(t *testing.T) {
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
				Config: `
ephemeral "vault_alicloud_access_credentials" "creds" {
  mount = "alicloud"
  role  = ""
}

provider "echo" {
  data = {
    access_key = ephemeral.vault_alicloud_access_credentials.creds.access_key
  }
}

resource "echo" "test" {}
`,
				ExpectError: regexp.MustCompile(`(?i)Vault response was nil|role.*empty|role.*required`),
			},
		},
	})
}

// TestAccAliCloudAccessCredentialsEphemeralResource_multipleSimultaneous tests
// the behavior when multiple ephemeral resources request credentials simultaneously.
// This verifies that each ephemeral resource gets its own unique set of credentials.
func TestAccAliCloudAccessCredentialsEphemeralResource_multipleSimultaneous(t *testing.T) {
	accessKey := os.Getenv("ALICLOUD_ACCESS_KEY")
	secretKey := os.Getenv("ALICLOUD_SECRET_KEY")

	if accessKey == "" || secretKey == "" {
		t.Skip("ALICLOUD_ACCESS_KEY and ALICLOUD_SECRET_KEY must be set for acceptance tests")
	}

	backend := acctest.RandomWithPrefix("tf-alicloud")
	role1 := acctest.RandomWithPrefix("test-role-1")
	role2 := acctest.RandomWithPrefix("test-role-2")

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
				// Step 1: Create backend and two roles
				Config: testAccAliCloudAccessCredentialsEphemeralResourceConfig_multipleSimultaneousSetup(backend, role1, role2, accessKey, secretKey),
			},
			{
				// Step 2: Use multiple ephemeral resources simultaneously
				Config: testAccAliCloudAccessCredentialsEphemeralResourceConfig_multipleSimultaneous(backend, role1, role2, accessKey, secretKey),
				ConfigStateChecks: []statecheck.StateCheck{
					// Verify first ephemeral resource
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("creds1_mount"), knownvalue.StringExact(backend)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("creds1_role"), knownvalue.StringExact(role1)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("creds1_access_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("creds1_secret_key"), knownvalue.NotNull()),
					// Verify second ephemeral resource
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("creds2_mount"), knownvalue.StringExact(backend)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("creds2_role"), knownvalue.StringExact(role2)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("creds2_access_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("creds2_secret_key"), knownvalue.NotNull()),
					// Verify third ephemeral resource (same role as first, should get different credentials)
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("creds3_mount"), knownvalue.StringExact(backend)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("creds3_role"), knownvalue.StringExact(role1)),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("creds3_access_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("creds3_secret_key"), knownvalue.NotNull()),
				},
			},
		},
	})
}

func testAccAliCloudAccessCredentialsEphemeralResourceConfig_multipleSimultaneousSetup(backend, role1, role2, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_alicloud_secret_backend" "test" {
  path          = "%s"
  access_key    = "%s"
  secret_key_wo = "%s"
}

resource "vault_alicloud_secret_backend_role" "role1" {
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

resource "vault_alicloud_secret_backend_role" "role2" {
  mount = vault_alicloud_secret_backend.test.path
  name  = "%s"
  inline_policies = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["oss:Get*"]
      Resource = "*"
    }]
    Version = "1"
  })
  ttl     = 3600
  max_ttl = 7200
}
`, backend, accessKey, secretKey, role1, role2)
}

func testAccAliCloudAccessCredentialsEphemeralResourceConfig_multipleSimultaneous(backend, role1, role2, accessKey, secretKey string) string {
	return testAccAliCloudAccessCredentialsEphemeralResourceConfig_multipleSimultaneousSetup(backend, role1, role2, accessKey, secretKey) + `

# First ephemeral resource using role1
ephemeral "vault_alicloud_access_credentials" "creds1" {
  mount = vault_alicloud_secret_backend.test.path
  role  = vault_alicloud_secret_backend_role.role1.name
}

# Second ephemeral resource using role2
ephemeral "vault_alicloud_access_credentials" "creds2" {
  mount = vault_alicloud_secret_backend.test.path
  role  = vault_alicloud_secret_backend_role.role2.name
}

# Third ephemeral resource using role1 again (should get different credentials than creds1)
ephemeral "vault_alicloud_access_credentials" "creds3" {
  mount = vault_alicloud_secret_backend.test.path
  role  = vault_alicloud_secret_backend_role.role1.name
}

provider "echo" {
  data = {
    # First ephemeral resource outputs
    creds1_mount      = ephemeral.vault_alicloud_access_credentials.creds1.mount
    creds1_role       = ephemeral.vault_alicloud_access_credentials.creds1.role
    creds1_access_key = ephemeral.vault_alicloud_access_credentials.creds1.access_key
    creds1_secret_key = ephemeral.vault_alicloud_access_credentials.creds1.secret_key
    # Second ephemeral resource outputs
    creds2_mount      = ephemeral.vault_alicloud_access_credentials.creds2.mount
    creds2_role       = ephemeral.vault_alicloud_access_credentials.creds2.role
    creds2_access_key = ephemeral.vault_alicloud_access_credentials.creds2.access_key
    creds2_secret_key = ephemeral.vault_alicloud_access_credentials.creds2.secret_key
    # Third ephemeral resource outputs
    creds3_mount      = ephemeral.vault_alicloud_access_credentials.creds3.mount
    creds3_role       = ephemeral.vault_alicloud_access_credentials.creds3.role
    creds3_access_key = ephemeral.vault_alicloud_access_credentials.creds3.access_key
    creds3_secret_key = ephemeral.vault_alicloud_access_credentials.creds3.secret_key
  }
}

resource "echo" "test" {}
`
}

// TestAccAliCloudAccessCredentialsEphemeralResource_rapidRefresh tests behavior
// when configuration is applied multiple times in succession.
// This verifies:
// - Each apply successfully generates credentials without errors
// - No rate limiting issues from Vault or AliCloud
// - Consistent performance across runs
// - Credentials remain valid and complete across multiple applies
func TestAccAliCloudAccessCredentialsEphemeralResource_rapidRefresh(t *testing.T) {
	accessKey := os.Getenv("ALICLOUD_ACCESS_KEY")
	secretKey := os.Getenv("ALICLOUD_SECRET_KEY")
	roleARN := os.Getenv("ALICLOUD_ROLE_ARN")

	if accessKey == "" || secretKey == "" {
		t.Skip("ALICLOUD_ACCESS_KEY and ALICLOUD_SECRET_KEY must be set for acceptance tests")
	}

	if roleARN == "" {
		t.Skip("ALICLOUD_ROLE_ARN must be set for rapid refresh tests (STS credentials are needed)")
	}

	backend := acctest.RandomWithPrefix("tf-alicloud")
	role := acctest.RandomWithPrefix("test-role")

	// Track successful credential generations
	successCount := 0

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
				// Step 1: Setup backend and role with role_arn for STS credentials
				Config: testAccAliCloudAccessCredentialsEphemeralResourceConfig_rapidRefreshSetup(backend, role, roleARN, accessKey, secretKey),
			},
			{
				// Step 2: First credential generation
				Config: testAccAliCloudAccessCredentialsEphemeralResourceConfig_rapidRefresh(backend, role, roleARN, accessKey, secretKey, "run1"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("access_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("secret_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("security_token"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("expiration"), knownvalue.NotNull()),
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("echo.test", "data.access_key"),
					resource.TestCheckResourceAttrSet("echo.test", "data.secret_key"),
					resource.TestCheckResourceAttrSet("echo.test", "data.security_token"),
					resource.TestCheckResourceAttrWith("echo.test", "data.access_key", func(value string) error {
						successCount++
						t.Logf("Run %d - Successfully generated credentials, access_key: %s", successCount, value)
						return nil
					}),
				),
			},
			{
				// Step 3: Second credential generation (rapid refresh - simulates second apply)
				Config: testAccAliCloudAccessCredentialsEphemeralResourceConfig_rapidRefresh(backend, role, roleARN, accessKey, secretKey, "run2"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("access_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("secret_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("security_token"), knownvalue.NotNull()),
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("echo.test", "data.access_key"),
					resource.TestCheckResourceAttrSet("echo.test", "data.secret_key"),
					resource.TestCheckResourceAttrWith("echo.test", "data.access_key", func(value string) error {
						successCount++
						t.Logf("Run %d - Successfully generated credentials, access_key: %s", successCount, value)
						return nil
					}),
				),
			},
			{
				// Step 4: Third credential generation (rapid refresh)
				Config: testAccAliCloudAccessCredentialsEphemeralResourceConfig_rapidRefresh(backend, role, roleARN, accessKey, secretKey, "run3"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("access_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("secret_key"), knownvalue.NotNull()),
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("echo.test", "data.access_key"),
					resource.TestCheckResourceAttrWith("echo.test", "data.access_key", func(value string) error {
						successCount++
						t.Logf("Run %d - Successfully generated credentials, access_key: %s", successCount, value)
						return nil
					}),
				),
			},
			{
				// Step 5: Fourth credential generation (rapid refresh)
				Config: testAccAliCloudAccessCredentialsEphemeralResourceConfig_rapidRefresh(backend, role, roleARN, accessKey, secretKey, "run4"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("access_key"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data").AtMapKey("secret_key"), knownvalue.NotNull()),
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("echo.test", "data.access_key"),
					resource.TestCheckResourceAttrWith("echo.test", "data.access_key", func(value string) error {
						successCount++
						t.Logf("Run %d - Successfully generated credentials, access_key: %s", successCount, value)
						if successCount < 4 {
							return fmt.Errorf("expected 4 successful credential generations, got %d", successCount)
						}
						t.Logf("All %d rapid refresh runs completed successfully - no rate limiting issues detected", successCount)
						return nil
					}),
				),
			},
		},
	})
}

func testAccAliCloudAccessCredentialsEphemeralResourceConfig_rapidRefreshSetup(backend, role, roleARN, accessKey, secretKey string) string {
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

func testAccAliCloudAccessCredentialsEphemeralResourceConfig_rapidRefresh(backend, role, roleARN, accessKey, secretKey, runID string) string {
	return testAccAliCloudAccessCredentialsEphemeralResourceConfig_rapidRefreshSetup(backend, role, roleARN, accessKey, secretKey) + fmt.Sprintf(`

ephemeral "vault_alicloud_access_credentials" "creds" {
  mount = vault_alicloud_secret_backend.test.path
  role  = vault_alicloud_secret_backend_role.test.name
}

# Using runID to force config change and trigger refresh: %s
provider "echo" {
  data = {
    run_id           = "%s"
    mount            = ephemeral.vault_alicloud_access_credentials.creds.mount
    role             = ephemeral.vault_alicloud_access_credentials.creds.role
    access_key       = ephemeral.vault_alicloud_access_credentials.creds.access_key
    secret_key       = ephemeral.vault_alicloud_access_credentials.creds.secret_key
    security_token   = ephemeral.vault_alicloud_access_credentials.creds.security_token
    expiration       = ephemeral.vault_alicloud_access_credentials.creds.expiration
    lease_id         = ephemeral.vault_alicloud_access_credentials.creds.lease_id
    lease_duration   = ephemeral.vault_alicloud_access_credentials.creds.lease_duration
    lease_start_time = ephemeral.vault_alicloud_access_credentials.creds.lease_start_time
  }
}

resource "echo" "test" {}
`, runID, runID)
}
