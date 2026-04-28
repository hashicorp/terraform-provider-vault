// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package alicloud_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

const (
	testAccAliCloudSecretBackendRoleInlinePolicy_basic = `{"Statement":[{"Action":["oss:GetObject","oss:PutObject"],"Effect":"Allow","Resource":["acs:oss:*:*:my-bucket/*"]}],"Version":"1"}`

	testAccAliCloudSecretBackendRoleInlinePolicy_updated = `{"Statement":[{"Action":["ecs:DescribeInstances","ecs:StartInstance"],"Effect":"Allow","Resource":["*"]}],"Version":"1"}`

	testAccAliCloudSecretBackendRoleRoleARN_basic   = "acs:ram::123456789012:role/TestRole"
	testAccAliCloudSecretBackendRoleRoleARN_updated = "acs:ram::123456789012:role/UpdatedRole"
)

// TestAccAliCloudSecretBackendRole_basic tests basic CRUD operations with all credential types
func TestAccAliCloudSecretBackendRole_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-alicloud")
	name := acctest.RandomWithPrefix("tf-test-role")
	accessKey, secretKey := getTestAliCloudCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAliCloudSecretBackendRoleConfig_basic(name, backend, accessKey, secretKey),
				Check:  testAccAliCloudSecretBackendRoleCheck_basic(name, backend),
			},
			{
				Config: testAccAliCloudSecretBackendRoleConfig_updated(name, backend, accessKey, secretKey),
				Check:  testAccAliCloudSecretBackendRoleCheck_updated(name, backend),
			},
		},
	})
}

// TestAccAliCloudSecretBackendRole_remotePolicyLifecycle tests remote policy config and import.
func TestAccAliCloudSecretBackendRole_remotePolicyLifecycle(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-alicloud")
	name := acctest.RandomWithPrefix("tf-test-role")
	accessKey, secretKey := getTestAliCloudCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAliCloudSecretBackendRoleConfig_remotePolicy(name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldName, name),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldMount, backend),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldRemotePolicies+".#", "2"),
					resource.TestCheckTypeSetElemNestedAttrs("vault_alicloud_secret_backend_role.test", consts.FieldRemotePolicies+".*", map[string]string{
						consts.FieldName: "AliyunOSSReadOnlyAccess",
						consts.FieldType: "System",
					}),
					resource.TestCheckTypeSetElemNestedAttrs("vault_alicloud_secret_backend_role.test", consts.FieldRemotePolicies+".*", map[string]string{
						consts.FieldName: "AliyunECSReadOnlyAccess",
						consts.FieldType: "System",
					}),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldTTL, "3600"),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldMaxTTL, "7200"),
				),
			},
			{
				ResourceName:                         "vault_alicloud_secret_backend_role.test",
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateIdFunc:                    testAccAliCloudSecretBackendRoleImportStateIdFunc("vault_alicloud_secret_backend_role.test"),
			},
		},
	})
}

// TestAccAliCloudSecretBackendRole_minimal tests minimal configuration (role_arn only, no TTL)
func TestAccAliCloudSecretBackendRole_minimal(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-alicloud")
	name := acctest.RandomWithPrefix("tf-test-role")
	accessKey, secretKey := getTestAliCloudCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAliCloudSecretBackendRoleConfig_minimal(name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldName, name),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldMount, backend),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldRoleArn, testAccAliCloudSecretBackendRoleRoleARN_basic),
				),
			},
		},
	})
}

// TestAccAliCloudSecretBackendRole_ttlOnly tests setting only TTL without MaxTTL
func TestAccAliCloudSecretBackendRole_ttlOnly(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-alicloud")
	name := acctest.RandomWithPrefix("tf-test-role")
	accessKey, secretKey := getTestAliCloudCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAliCloudSecretBackendRoleConfig_ttlOnly(name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldName, name),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldMount, backend),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldRoleArn, testAccAliCloudSecretBackendRoleRoleARN_basic),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldTTL, "1800"),
				),
			},
		},
	})
}

// TestAccAliCloudSecretBackendRole_maxTtlOnly tests setting only MaxTTL without TTL
func TestAccAliCloudSecretBackendRole_maxTtlOnly(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-alicloud")
	name := acctest.RandomWithPrefix("tf-test-role")
	accessKey, secretKey := getTestAliCloudCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAliCloudSecretBackendRoleConfig_maxTtlOnly(name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldName, name),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldMount, backend),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldRoleArn, testAccAliCloudSecretBackendRoleRoleARN_basic),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldMaxTTL, "7200"),
				),
			},
		},
	})
}

func TestAccAliCloudSecretBackendRole_importState(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-alicloud")
	name := acctest.RandomWithPrefix("tf-test-role")
	accessKey, secretKey := getTestAliCloudCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAliCloudSecretBackendRoleConfig_minimal(name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldName, name),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldMount, backend),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldRoleArn, testAccAliCloudSecretBackendRoleRoleARN_basic),
				),
			},
			{
				ResourceName:                         "vault_alicloud_secret_backend_role.test",
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: consts.FieldMount,
				ImportStateIdFunc:                    testAccAliCloudSecretBackendRoleImportStateIdFunc("vault_alicloud_secret_backend_role.test"),
			},
			{
				ResourceName:  "vault_alicloud_secret_backend_role.test",
				ImportState:   true,
				ImportStateId: fmt.Sprintf("%s/role/%s.", backend, name),
				ExpectError:   regexp.MustCompile(`Invalid Import ID`),
			},
		},
	})
}

// TestAccAliCloudSecretBackendRole_validation groups single-step role validation tests.
func TestAccAliCloudSecretBackendRole_validation(t *testing.T) {
	accessKey, secretKey := getTestAliCloudCreds(t)

	testCases := []struct {
		name        string
		config      string
		expectError string
	}{
		{
			name:        "missing_name",
			config:      testAccAliCloudSecretBackendRoleConfig_missingName(acctest.RandomWithPrefix("tf-test-alicloud"), accessKey, secretKey),
			expectError: `The argument "name" is required`,
		},
		{
			name:        "missing_mount",
			config:      testAccAliCloudSecretBackendRoleConfig_missingMount(acctest.RandomWithPrefix("tf-test-role")),
			expectError: `The argument "mount" is required`,
		},
		{
			name:        "no_credential_type",
			config:      testAccAliCloudSecretBackendRoleConfig_noCredentialType(acctest.RandomWithPrefix("tf-test-role"), acctest.RandomWithPrefix("tf-test-alicloud"), accessKey, secretKey),
			expectError: `must include an arn, or at least one of inline_policies or remote_policies`,
		},
		{
			name:        "empty_name",
			config:      testAccAliCloudSecretBackendRoleConfig_emptyName(acctest.RandomWithPrefix("tf-test-alicloud"), accessKey, secretKey),
			expectError: `unsupported operation`,
		},
		{
			name:        "conflict_role_arn_inline_policies",
			config:      testAccAliCloudSecretBackendRoleConfig_conflictRoleArnWithInlinePolicies(acctest.RandomWithPrefix("tf-test-role"), acctest.RandomWithPrefix("tf-test-alicloud"), accessKey, secretKey),
			expectError: `Conflicting configuration arguments`,
		},
		{
			name:        "conflict_role_arn_remote_policies",
			config:      testAccAliCloudSecretBackendRoleConfig_conflictRoleArnWithRemotePolicies(acctest.RandomWithPrefix("tf-test-role"), acctest.RandomWithPrefix("tf-test-alicloud"), accessKey, secretKey),
			expectError: `Conflicting configuration arguments`,
		},
		{
			name:        "conflict_role_arn_both_policies",
			config:      testAccAliCloudSecretBackendRoleConfig_conflictRoleArnWithBothPolicies(acctest.RandomWithPrefix("tf-test-role"), acctest.RandomWithPrefix("tf-test-alicloud"), accessKey, secretKey),
			expectError: `Conflicting configuration arguments`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
				ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config:      tc.config,
						ExpectError: regexp.MustCompile(tc.expectError),
					},
				},
			})
		})
	}
}

// TestAccAliCloudSecretBackendRole_defaultNamespace tests role creation without explicit namespace
func TestAccAliCloudSecretBackendRole_defaultNamespace(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-alicloud")
	name := acctest.RandomWithPrefix("tf-test-role")
	accessKey, secretKey := getTestAliCloudCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAliCloudSecretBackendRoleConfig_defaultNamespace(name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldName, name),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldMount, backend),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldTTL, "3600"),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldMaxTTL, "7200"),
					// When namespace is not specified, it should not be in state
					resource.TestCheckNoResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldNamespace),
				),
			},
		},
	})
}

// TestAccAliCloudSecretBackendRole_namespaceLifecycle tests create and update in a custom namespace.
func TestAccAliCloudSecretBackendRole_namespaceLifecycle(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-alicloud")
	name := acctest.RandomWithPrefix("tf-test-role")
	namespacePath := acctest.RandomWithPrefix("test-namespace")
	accessKey, secretKey := getTestAliCloudCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAliCloudSecretBackendRoleConfig_namespace(namespacePath, name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldName, name),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldMount, backend),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldNamespace, namespacePath),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldRoleArn, testAccAliCloudSecretBackendRoleRoleARN_basic),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldTTL, "3600"),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldMaxTTL, "7200"),
				),
			},
			{
				Config: testAccAliCloudSecretBackendRoleConfig_namespaceUpdated(namespacePath, name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldName, name),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldMount, backend),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldNamespace, namespacePath),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldRoleArn, testAccAliCloudSecretBackendRoleRoleARN_updated),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldTTL, "7200"),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", consts.FieldMaxTTL, "14400"),
				),
			},
		},
	})
}

// --- Check helper functions ---

func testAccAliCloudSecretBackendRoleCheck_basic(name, backend string) resource.TestCheckFunc {
	return resource.ComposeTestCheckFunc(
		// Inline policy role
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", consts.FieldName, fmt.Sprintf("%s-inline", name)),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", consts.FieldMount, backend),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", consts.FieldInlinePolicies+".#", "1"),
		resource.TestCheckTypeSetElemNestedAttrs("vault_alicloud_secret_backend_role.test_inline", consts.FieldInlinePolicies+".*", map[string]string{
			consts.FieldPolicyDocument: testAccAliCloudSecretBackendRoleInlinePolicy_basic,
		}),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", consts.FieldTTL, "3600"),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", consts.FieldMaxTTL, "7200"),

		// Remote policy role
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", consts.FieldName, fmt.Sprintf("%s-remote", name)),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", consts.FieldMount, backend),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", consts.FieldRemotePolicies+".#", "1"),
		resource.TestCheckTypeSetElemNestedAttrs("vault_alicloud_secret_backend_role.test_remote", consts.FieldRemotePolicies+".*", map[string]string{
			consts.FieldName: "AliyunOSSReadOnlyAccess",
			consts.FieldType: "System",
		}),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", consts.FieldTTL, "1800"),

		// Role ARN role
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", consts.FieldName, fmt.Sprintf("%s-role-arn", name)),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", consts.FieldMount, backend),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", consts.FieldRoleArn, testAccAliCloudSecretBackendRoleRoleARN_basic),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", consts.FieldTTL, "3600"),
	)
}

func testAccAliCloudSecretBackendRoleCheck_updated(name, backend string) resource.TestCheckFunc {
	return resource.ComposeTestCheckFunc(
		// Inline policy role - updated
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", consts.FieldName, fmt.Sprintf("%s-inline", name)),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", consts.FieldMount, backend),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", consts.FieldInlinePolicies+".#", "1"),
		resource.TestCheckTypeSetElemNestedAttrs("vault_alicloud_secret_backend_role.test_inline", consts.FieldInlinePolicies+".*", map[string]string{
			consts.FieldPolicyDocument: testAccAliCloudSecretBackendRoleInlinePolicy_updated,
		}),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", consts.FieldTTL, "7200"),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", consts.FieldMaxTTL, "14400"),

		// Remote policy role - updated
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", consts.FieldName, fmt.Sprintf("%s-remote", name)),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", consts.FieldMount, backend),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", consts.FieldRemotePolicies+".#", "2"),
		resource.TestCheckTypeSetElemNestedAttrs("vault_alicloud_secret_backend_role.test_remote", consts.FieldRemotePolicies+".*", map[string]string{
			consts.FieldName: "AliyunECSReadOnlyAccess",
			consts.FieldType: "System",
		}),
		resource.TestCheckTypeSetElemNestedAttrs("vault_alicloud_secret_backend_role.test_remote", consts.FieldRemotePolicies+".*", map[string]string{
			consts.FieldName: "AliyunRDSReadOnlyAccess",
			consts.FieldType: "System",
		}),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", consts.FieldTTL, "3600"),

		// Role ARN role - updated
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", consts.FieldName, fmt.Sprintf("%s-role-arn", name)),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", consts.FieldMount, backend),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", consts.FieldRoleArn, testAccAliCloudSecretBackendRoleRoleARN_updated),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", consts.FieldTTL, "7200"),
	)
}

// --- Config helper functions ---

func testAccAliCloudSecretBackendRoleConfig_basic(name, backend, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "alicloud"
}

resource "vault_alicloud_secret_backend" "test" {
  mount         = vault_mount.test.path
  access_key    = %q
  secret_key_wo = %q
  secret_key_wo_version = 1
}

resource "vault_alicloud_secret_backend_role" "test_inline" {
  mount = vault_mount.test.path
  name  = "%s-inline"

  inline_policies {
    policy_document = %q
  }

  ttl     = 3600
  max_ttl = 7200
}

resource "vault_alicloud_secret_backend_role" "test_remote" {
  mount = vault_mount.test.path
  name  = "%s-remote"

  remote_policies {
    name = "AliyunOSSReadOnlyAccess"
    type = "System"
  }

  ttl = 1800
}

resource "vault_alicloud_secret_backend_role" "test_role_arn" {
  mount    = vault_mount.test.path
  name     = "%s-role-arn"
  role_arn = %q

  ttl = 3600
}
`, backend, accessKey, secretKey, name, testAccAliCloudSecretBackendRoleInlinePolicy_basic, name, name, testAccAliCloudSecretBackendRoleRoleARN_basic)
}

func testAccAliCloudSecretBackendRoleConfig_updated(name, backend, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "alicloud"
}

resource "vault_alicloud_secret_backend" "test" {
  mount         = vault_mount.test.path
  access_key    = %q
  secret_key_wo = %q
  secret_key_wo_version = 1
}

resource "vault_alicloud_secret_backend_role" "test_inline" {
  mount = vault_mount.test.path
  name  = "%s-inline"

  inline_policies {
    policy_document = %q
  }

  ttl     = 7200
  max_ttl = 14400
}

resource "vault_alicloud_secret_backend_role" "test_remote" {
  mount = vault_mount.test.path
  name  = "%s-remote"

  remote_policies {
    name = "AliyunECSReadOnlyAccess"
    type = "System"
  }

  remote_policies {
    name = "AliyunRDSReadOnlyAccess"
    type = "System"
  }

  ttl = 3600
}

resource "vault_alicloud_secret_backend_role" "test_role_arn" {
  mount    = vault_mount.test.path
  name     = "%s-role-arn"
  role_arn = %q

  ttl = 7200
}
`, backend, accessKey, secretKey, name, testAccAliCloudSecretBackendRoleInlinePolicy_updated, name, name, testAccAliCloudSecretBackendRoleRoleARN_updated)
}

func testAccAliCloudSecretBackendRoleConfig_remotePolicy(name, backend, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "alicloud"
}

resource "vault_alicloud_secret_backend" "test" {
  mount         = vault_mount.test.path
  access_key    = %q
  secret_key_wo = %q
  secret_key_wo_version = 1
}

resource "vault_alicloud_secret_backend_role" "test" {
  mount = vault_mount.test.path
  name  = %q

  remote_policies {
    name = "AliyunOSSReadOnlyAccess"
    type = "System"
  }

  remote_policies {
    name = "AliyunECSReadOnlyAccess"
    type = "System"
  }

  ttl     = 3600
  max_ttl = 7200
}
`, backend, accessKey, secretKey, name)
}

func testAccAliCloudSecretBackendRoleConfig_minimal(name, backend, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "alicloud"
}

resource "vault_alicloud_secret_backend" "test" {
  mount         = vault_mount.test.path
  access_key    = %q
  secret_key_wo = %q
  secret_key_wo_version = 1
}

resource "vault_alicloud_secret_backend_role" "test" {
  mount    = vault_mount.test.path
  name     = %q
  role_arn = %q
}
`, backend, accessKey, secretKey, name, testAccAliCloudSecretBackendRoleRoleARN_basic)
}

func testAccAliCloudSecretBackendRoleConfig_ttlOnly(name, backend, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "alicloud"
}

resource "vault_alicloud_secret_backend" "test" {
  mount         = vault_mount.test.path
  access_key    = %q
  secret_key_wo = %q
  secret_key_wo_version = 1
}

resource "vault_alicloud_secret_backend_role" "test" {
  mount    = vault_mount.test.path
  name     = %q
  role_arn = %q
  ttl      = 1800
}
`, backend, accessKey, secretKey, name, testAccAliCloudSecretBackendRoleRoleARN_basic)
}

func testAccAliCloudSecretBackendRoleConfig_maxTtlOnly(name, backend, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "alicloud"
}

resource "vault_alicloud_secret_backend" "test" {
  mount         = vault_mount.test.path
  access_key    = %q
  secret_key_wo = %q
  secret_key_wo_version = 1
}

resource "vault_alicloud_secret_backend_role" "test" {
  mount    = vault_mount.test.path
  name     = %q
  role_arn = %q
  max_ttl  = 7200
}
`, backend, accessKey, secretKey, name, testAccAliCloudSecretBackendRoleRoleARN_basic)
}

func testAccAliCloudSecretBackendRoleConfig_missingName(backend, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "alicloud"
}

resource "vault_alicloud_secret_backend" "test" {
  mount         = vault_mount.test.path
  access_key    = %q
  secret_key_wo = %q
  secret_key_wo_version = 1
}

resource "vault_alicloud_secret_backend_role" "test" {
  mount    = vault_mount.test.path
  role_arn = %q
}
`, backend, accessKey, secretKey, testAccAliCloudSecretBackendRoleRoleARN_basic)
}

func testAccAliCloudSecretBackendRoleConfig_missingMount(name string) string {
	return fmt.Sprintf(`
resource "vault_alicloud_secret_backend_role" "test" {
  name     = %q
  role_arn = %q
}
`, name, testAccAliCloudSecretBackendRoleRoleARN_basic)
}

func testAccAliCloudSecretBackendRoleConfig_noCredentialType(name, backend, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "alicloud"
}

resource "vault_alicloud_secret_backend" "test" {
  mount         = vault_mount.test.path
  access_key    = %q
  secret_key_wo = %q
  secret_key_wo_version = 1
}

resource "vault_alicloud_secret_backend_role" "test" {
  mount = vault_mount.test.path
  name  = %q
  ttl   = 3600
}
`, backend, accessKey, secretKey, name)
}

func testAccAliCloudSecretBackendRoleConfig_emptyName(backend, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "alicloud"
}

resource "vault_alicloud_secret_backend" "test" {
  mount         = vault_mount.test.path
  access_key    = %q
  secret_key_wo = %q
  secret_key_wo_version = 1
}

resource "vault_alicloud_secret_backend_role" "test" {
  mount    = vault_mount.test.path
  name     = ""
  role_arn = %q
}
`, backend, accessKey, secretKey, testAccAliCloudSecretBackendRoleRoleARN_basic)
}

func testAccAliCloudSecretBackendRoleConfig_defaultNamespace(name, backend, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "alicloud"
}

resource "vault_alicloud_secret_backend" "test" {
  mount         = vault_mount.test.path
  access_key    = %q
  secret_key_wo = %q
  secret_key_wo_version = 1
}

resource "vault_alicloud_secret_backend_role" "test" {
  mount    = vault_mount.test.path
  name     = %q
  role_arn = %q
  ttl      = 3600
  max_ttl  = 7200
}
`, backend, accessKey, secretKey, name, testAccAliCloudSecretBackendRoleRoleARN_basic)
}

func testAccAliCloudSecretBackendRoleConfig_conflictRoleArnWithInlinePolicies(name, backend, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "alicloud"
}

resource "vault_alicloud_secret_backend" "test" {
  mount         = vault_mount.test.path
  access_key    = %q
  secret_key_wo = %q
  secret_key_wo_version = 1
}

resource "vault_alicloud_secret_backend_role" "test" {
  mount    = vault_mount.test.path
  name     = %q
  role_arn = %q

  inline_policies {
    policy_document = %q
  }
}
`, backend, accessKey, secretKey, name, testAccAliCloudSecretBackendRoleRoleARN_basic, testAccAliCloudSecretBackendRoleInlinePolicy_basic)
}

func testAccAliCloudSecretBackendRoleConfig_conflictRoleArnWithRemotePolicies(name, backend, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "alicloud"
}

resource "vault_alicloud_secret_backend" "test" {
  mount         = vault_mount.test.path
  access_key    = %q
  secret_key_wo = %q
  secret_key_wo_version = 1
}

resource "vault_alicloud_secret_backend_role" "test" {
  mount    = vault_mount.test.path
  name     = %q
  role_arn = %q

  remote_policies {
    name = "AliyunOSSReadOnlyAccess"
    type = "System"
  }
}
`, backend, accessKey, secretKey, name, testAccAliCloudSecretBackendRoleRoleARN_basic)
}

func testAccAliCloudSecretBackendRoleConfig_conflictRoleArnWithBothPolicies(name, backend, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "alicloud"
}

resource "vault_alicloud_secret_backend" "test" {
  mount         = vault_mount.test.path
  access_key    = %q
  secret_key_wo = %q
  secret_key_wo_version = 1
}

resource "vault_alicloud_secret_backend_role" "test" {
  mount    = vault_mount.test.path
  name     = %q
  role_arn = %q

  inline_policies {
    policy_document = %q
  }

  remote_policies {
    name = "AliyunOSSReadOnlyAccess"
    type = "System"
  }
}
`, backend, accessKey, secretKey, name, testAccAliCloudSecretBackendRoleRoleARN_basic, testAccAliCloudSecretBackendRoleInlinePolicy_basic)
}

func testAccAliCloudSecretBackendRoleConfig_namespace(namespacePath, name, backend, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = %q
}

resource "vault_mount" "test" {
  namespace = vault_namespace.test.path
  path      = %q
  type      = "alicloud"
}

resource "vault_alicloud_secret_backend" "test" {
  namespace     = vault_namespace.test.path
  mount         = vault_mount.test.path
  access_key    = %q
  secret_key_wo = %q
  secret_key_wo_version = 1
}

resource "vault_alicloud_secret_backend_role" "test" {
  namespace = vault_namespace.test.path
  mount     = vault_mount.test.path
  name      = %q
  role_arn  = %q
  ttl       = 3600
  max_ttl   = 7200
}
`, namespacePath, backend, accessKey, secretKey, name, testAccAliCloudSecretBackendRoleRoleARN_basic)
}

func testAccAliCloudSecretBackendRoleConfig_namespaceUpdated(namespacePath, name, backend, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = %q
}

resource "vault_mount" "test" {
  namespace = vault_namespace.test.path
  path      = %q
  type      = "alicloud"
}

resource "vault_alicloud_secret_backend" "test" {
  namespace     = vault_namespace.test.path
  mount         = vault_mount.test.path
  access_key    = %q
  secret_key_wo = %q
  secret_key_wo_version = 1
}

resource "vault_alicloud_secret_backend_role" "test" {
  namespace = vault_namespace.test.path
  mount     = vault_mount.test.path
  name      = %q
  role_arn  = %q
  ttl       = 7200
  max_ttl   = 14400
}
`, namespacePath, backend, accessKey, secretKey, name, testAccAliCloudSecretBackendRoleRoleARN_updated)
}

// testAccAliCloudSecretBackendRoleImportStateIdFunc returns a function that constructs
// the import ID for a role resource by reading its mount and name from state
func testAccAliCloudSecretBackendRoleImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("resource not found: %s", resourceName)
		}

		mount := rs.Primary.Attributes[consts.FieldMount]
		name := rs.Primary.Attributes[consts.FieldName]

		if mount == "" || name == "" {
			return "", fmt.Errorf("mount or name not found in resource attributes")
		}

		return fmt.Sprintf("%s/role/%s", mount, name), nil
	}
}
