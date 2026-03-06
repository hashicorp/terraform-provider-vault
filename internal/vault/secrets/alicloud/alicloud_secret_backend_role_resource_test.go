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

// TestAccAliCloudSecretBackendRole_import tests import state functionality
func TestAccAliCloudSecretBackendRole_import(t *testing.T) {
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
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "mount", backend),
				),
			},
			{
				ResourceName:                         "vault_alicloud_secret_backend_role.test",
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "mount",
				ImportStateIdFunc:                    testAccAliCloudSecretBackendRoleImportStateIdFunc("vault_alicloud_secret_backend_role.test"),
			},
		},
	})
}

// TestAccAliCloudSecretBackendRole_remotePolicy tests remote policy configuration
func TestAccAliCloudSecretBackendRole_remotePolicy(t *testing.T) {
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
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "mount", backend),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "remote_policies.#", "2"),
					resource.TestCheckTypeSetElemNestedAttrs("vault_alicloud_secret_backend_role.test", "remote_policies.*", map[string]string{
						"name": "AliyunOSSReadOnlyAccess",
						"type": "System",
					}),
					resource.TestCheckTypeSetElemNestedAttrs("vault_alicloud_secret_backend_role.test", "remote_policies.*", map[string]string{
						"name": "AliyunECSReadOnlyAccess",
						"type": "System",
					}),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "ttl", "3600"),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "max_ttl", "7200"),
				),
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
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "mount", backend),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "role_arn", testAccAliCloudSecretBackendRoleRoleARN_basic),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "ttl", "0"),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "max_ttl", "0"),
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
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "mount", backend),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "role_arn", testAccAliCloudSecretBackendRoleRoleARN_basic),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "ttl", "1800"),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "max_ttl", "0"),
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
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "mount", backend),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "role_arn", testAccAliCloudSecretBackendRoleRoleARN_basic),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "ttl", "0"),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "max_ttl", "7200"),
				),
			},
		},
	})
}

// TestAccAliCloudSecretBackendRole_multipleRemotePolicies tests multiple remote policies
func TestAccAliCloudSecretBackendRole_multipleRemotePolicies(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-alicloud")
	name := acctest.RandomWithPrefix("tf-test-role")
	accessKey, secretKey := getTestAliCloudCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAliCloudSecretBackendRoleConfig_multipleRemotePolicies(name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "mount", backend),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "remote_policies.#", "3"),
					resource.TestCheckTypeSetElemNestedAttrs("vault_alicloud_secret_backend_role.test", "remote_policies.*", map[string]string{
						"name": "AliyunOSSReadOnlyAccess",
						"type": "System",
					}),
					resource.TestCheckTypeSetElemNestedAttrs("vault_alicloud_secret_backend_role.test", "remote_policies.*", map[string]string{
						"name": "AliyunECSReadOnlyAccess",
						"type": "System",
					}),
					resource.TestCheckTypeSetElemNestedAttrs("vault_alicloud_secret_backend_role.test", "remote_policies.*", map[string]string{
						"name": "AliyunRDSReadOnlyAccess",
						"type": "System",
					}),
				),
			},
		},
	})
}

// TestAccAliCloudSecretBackendRole_missingName tests validation when name is missing
func TestAccAliCloudSecretBackendRole_missingName(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-alicloud")
	accessKey, secretKey := getTestAliCloudCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccAliCloudSecretBackendRoleConfig_missingName(backend, accessKey, secretKey),
				ExpectError: regexp.MustCompile(`The argument "name" is required`),
			},
		},
	})
}

// TestAccAliCloudSecretBackendRole_missingMount tests validation when mount is missing
func TestAccAliCloudSecretBackendRole_missingMount(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-test-role")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccAliCloudSecretBackendRoleConfig_missingMount(name),
				ExpectError: regexp.MustCompile(`The argument "mount" is required`),
			},
		},
	})
}

// TestAccAliCloudSecretBackendRole_noCredentialType tests error when no credential type specified
func TestAccAliCloudSecretBackendRole_noCredentialType(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-alicloud")
	name := acctest.RandomWithPrefix("tf-test-role")
	accessKey, secretKey := getTestAliCloudCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccAliCloudSecretBackendRoleConfig_noCredentialType(name, backend, accessKey, secretKey),
				ExpectError: regexp.MustCompile(`must include an arn, or at least one of inline_policies or remote_policies`),
			},
		},
	})
}

// TestAccAliCloudSecretBackendRole_emptyName tests error when name is empty
func TestAccAliCloudSecretBackendRole_emptyName(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-alicloud")
	accessKey, secretKey := getTestAliCloudCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccAliCloudSecretBackendRoleConfig_emptyName(backend, accessKey, secretKey),
				ExpectError: regexp.MustCompile(`unsupported operation`),
			},
		},
	})
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
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "mount", backend),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "ttl", "3600"),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "max_ttl", "7200"),
					// When namespace is not specified, it should not be in state
					resource.TestCheckNoResourceAttr("vault_alicloud_secret_backend_role.test", "namespace"),
				),
			},
		},
	})
}

// TestAccAliCloudSecretBackendRole_namespace tests role creation in a custom namespace
func TestAccAliCloudSecretBackendRole_namespace(t *testing.T) {
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
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "mount", backend),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "namespace", namespacePath),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "role_arn", testAccAliCloudSecretBackendRoleRoleARN_basic),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "ttl", "3600"),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "max_ttl", "7200"),
				),
			},
		},
	})
}

// TestAccAliCloudSecretBackendRole_namespaceUpdate tests updating role in a namespace
func TestAccAliCloudSecretBackendRole_namespaceUpdate(t *testing.T) {
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
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "mount", backend),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "namespace", namespacePath),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "role_arn", testAccAliCloudSecretBackendRoleRoleARN_basic),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "ttl", "3600"),
				),
			},
			{
				Config: testAccAliCloudSecretBackendRoleConfig_namespaceUpdated(namespacePath, name, backend, accessKey, secretKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "name", name),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "mount", backend),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "namespace", namespacePath),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "role_arn", testAccAliCloudSecretBackendRoleRoleARN_updated),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "ttl", "7200"),
				),
			},
		},
	})
}

// TestAccAliCloudSecretBackendRole_conflictRoleArnWithInlinePolicies tests that role_arn conflicts with inline_policies
func TestAccAliCloudSecretBackendRole_conflictRoleArnWithInlinePolicies(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-alicloud")
	name := acctest.RandomWithPrefix("tf-test-role")
	accessKey, secretKey := getTestAliCloudCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccAliCloudSecretBackendRoleConfig_conflictRoleArnWithInlinePolicies(name, backend, accessKey, secretKey),
				ExpectError: regexp.MustCompile(`Conflicting configuration arguments`),
			},
		},
	})
}

// TestAccAliCloudSecretBackendRole_conflictRoleArnWithRemotePolicies tests that role_arn conflicts with remote_policies
func TestAccAliCloudSecretBackendRole_conflictRoleArnWithRemotePolicies(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-alicloud")
	name := acctest.RandomWithPrefix("tf-test-role")
	accessKey, secretKey := getTestAliCloudCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccAliCloudSecretBackendRoleConfig_conflictRoleArnWithRemotePolicies(name, backend, accessKey, secretKey),
				ExpectError: regexp.MustCompile(`Conflicting configuration arguments`),
			},
		},
	})
}

// TestAccAliCloudSecretBackendRole_conflictRoleArnWithBothPolicies tests that role_arn conflicts with both policy types
func TestAccAliCloudSecretBackendRole_conflictRoleArnWithBothPolicies(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-alicloud")
	name := acctest.RandomWithPrefix("tf-test-role")
	accessKey, secretKey := getTestAliCloudCreds(t)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccAliCloudSecretBackendRoleConfig_conflictRoleArnWithBothPolicies(name, backend, accessKey, secretKey),
				ExpectError: regexp.MustCompile(`Conflicting configuration arguments`),
			},
		},
	})
}

// --- Check helper functions ---

func testAccAliCloudSecretBackendRoleCheck_basic(name, backend string) resource.TestCheckFunc {
	return resource.ComposeTestCheckFunc(
		// Inline policy role
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", "name", fmt.Sprintf("%s-inline", name)),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", "mount", backend),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", "inline_policies.#", "1"),
		resource.TestCheckTypeSetElemNestedAttrs("vault_alicloud_secret_backend_role.test_inline", "inline_policies.*", map[string]string{
			"policy_document": testAccAliCloudSecretBackendRoleInlinePolicy_basic,
		}),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", "ttl", "3600"),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", "max_ttl", "7200"),

		// Remote policy role
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", "name", fmt.Sprintf("%s-remote", name)),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", "mount", backend),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", "remote_policies.#", "1"),
		resource.TestCheckTypeSetElemNestedAttrs("vault_alicloud_secret_backend_role.test_remote", "remote_policies.*", map[string]string{
			"name": "AliyunOSSReadOnlyAccess",
			"type": "System",
		}),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", "ttl", "1800"),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", "max_ttl", "0"),

		// Role ARN role
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", "name", fmt.Sprintf("%s-role-arn", name)),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", "mount", backend),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", "role_arn", testAccAliCloudSecretBackendRoleRoleARN_basic),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", "ttl", "3600"),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", "max_ttl", "0"),
	)
}

func testAccAliCloudSecretBackendRoleCheck_updated(name, backend string) resource.TestCheckFunc {
	return resource.ComposeTestCheckFunc(
		// Inline policy role - updated
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", "name", fmt.Sprintf("%s-inline", name)),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", "mount", backend),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", "inline_policies.#", "1"),
		resource.TestCheckTypeSetElemNestedAttrs("vault_alicloud_secret_backend_role.test_inline", "inline_policies.*", map[string]string{
			"policy_document": testAccAliCloudSecretBackendRoleInlinePolicy_updated,
		}),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", "ttl", "7200"),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", "max_ttl", "14400"),

		// Remote policy role - updated
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", "name", fmt.Sprintf("%s-remote", name)),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", "mount", backend),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", "remote_policies.#", "2"),
		resource.TestCheckTypeSetElemNestedAttrs("vault_alicloud_secret_backend_role.test_remote", "remote_policies.*", map[string]string{
			"name": "AliyunECSReadOnlyAccess",
			"type": "System",
		}),
		resource.TestCheckTypeSetElemNestedAttrs("vault_alicloud_secret_backend_role.test_remote", "remote_policies.*", map[string]string{
			"name": "AliyunRDSReadOnlyAccess",
			"type": "System",
		}),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", "ttl", "3600"),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", "max_ttl", "0"),

		// Role ARN role - updated
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", "name", fmt.Sprintf("%s-role-arn", name)),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", "mount", backend),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", "role_arn", testAccAliCloudSecretBackendRoleRoleARN_updated),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", "ttl", "7200"),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", "max_ttl", "0"),
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
}

resource "vault_alicloud_secret_backend_role" "test" {
  mount    = vault_mount.test.path
  name     = %q
  role_arn = %q
  max_ttl  = 7200
}
`, backend, accessKey, secretKey, name, testAccAliCloudSecretBackendRoleRoleARN_basic)
}

func testAccAliCloudSecretBackendRoleConfig_multipleRemotePolicies(name, backend, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "alicloud"
}

resource "vault_alicloud_secret_backend" "test" {
  mount         = vault_mount.test.path
  access_key    = %q
  secret_key_wo = %q
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

  remote_policies {
    name = "AliyunRDSReadOnlyAccess"
    type = "System"
  }

  ttl     = 3600
  max_ttl = 7200
}
`, backend, accessKey, secretKey, name)
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

		mount := rs.Primary.Attributes["mount"]
		name := rs.Primary.Attributes["name"]

		if mount == "" || name == "" {
			return "", fmt.Errorf("mount or name not found in resource attributes")
		}

		return fmt.Sprintf("%s/role/%s", mount, name), nil
	}
}
