// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package alicloud_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

const (
	testAccAliCloudSecretBackendRoleInlinePolicy_basic = `{
  "Statement": [
    {
      "Action": [
        "oss:GetObject",
        "oss:PutObject"
      ],
      "Effect": "Allow",
      "Resource": [
        "acs:oss:*:*:my-bucket/*"
      ]
    }
  ],
  "Version": "1"
}`

	testAccAliCloudSecretBackendRoleInlinePolicy_updated = `{
  "Statement": [
    {
      "Action": [
        "ecs:DescribeInstances",
        "ecs:StartInstance"
      ],
      "Effect": "Allow",
      "Resource": [
        "*"
      ]
    }
  ],
  "Version": "1"
}`

	testAccAliCloudSecretBackendRoleRoleARN_basic   = "acs:ram::123456789012:role/TestRole"
	testAccAliCloudSecretBackendRoleRoleARN_updated = "acs:ram::123456789012:role/UpdatedRole"
)

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

func TestAccAliCloudSecretBackendRole_import(t *testing.T) {
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
				ResourceName:      "vault_alicloud_secret_backend_role.test_inline",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "vault_alicloud_secret_backend_role.test_remote",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "vault_alicloud_secret_backend_role.test_role_arn",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

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
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "remote_policies", "name:AliyunOSSReadOnlyAccess,type:System,name:AliyunECSReadOnlyAccess,type:System"),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "ttl", "3600"),
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "max_ttl", "7200"),
				),
			},
		},
	})
}

// TestAccAliCloudSecretBackendRole_minimal tests minimal configuration (no TTL values)
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
					resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test", "remote_policies", "name:AliyunOSSReadOnlyAccess,type:System,name:AliyunECSReadOnlyAccess,type:System,name:AliyunRDSReadOnlyAccess,type:System"),
				),
			},
		},
	})
}

func testAccAliCloudSecretBackendRoleCheck_basic(name, backend string) resource.TestCheckFunc {
	return resource.ComposeTestCheckFunc(
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", "name", fmt.Sprintf("%s-inline", name)),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", "mount", backend),
		testutil.TestCheckResourceAttrJSON("vault_alicloud_secret_backend_role.test_inline", "inline_policies", testAccAliCloudSecretBackendRoleInlinePolicy_basic),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", "ttl", "3600"),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", "max_ttl", "7200"),

		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", "name", fmt.Sprintf("%s-remote", name)),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", "mount", backend),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", "remote_policies", "name:AliyunOSSReadOnlyAccess,type:System"),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", "ttl", "1800"),

		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", "name", fmt.Sprintf("%s-role-arn", name)),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", "mount", backend),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", "role_arn", testAccAliCloudSecretBackendRoleRoleARN_basic),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", "ttl", "3600"),
	)
}

func testAccAliCloudSecretBackendRoleCheck_updated(name, backend string) resource.TestCheckFunc {
	return resource.ComposeTestCheckFunc(
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", "name", fmt.Sprintf("%s-inline", name)),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", "mount", backend),
		testutil.TestCheckResourceAttrJSON("vault_alicloud_secret_backend_role.test_inline", "inline_policies", testAccAliCloudSecretBackendRoleInlinePolicy_updated),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", "ttl", "7200"),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_inline", "max_ttl", "14400"),

		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", "name", fmt.Sprintf("%s-remote", name)),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", "mount", backend),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", "remote_policies", "name:AliyunECSReadOnlyAccess,type:System,name:AliyunRDSReadOnlyAccess,type:System"),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_remote", "ttl", "3600"),

		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", "name", fmt.Sprintf("%s-role-arn", name)),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", "mount", backend),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", "role_arn", testAccAliCloudSecretBackendRoleRoleARN_updated),
		resource.TestCheckResourceAttr("vault_alicloud_secret_backend_role.test_role_arn", "ttl", "7200"),
	)
}

func testAccAliCloudSecretBackendRoleConfig_basic(name, backend, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_alicloud_secret_backend" "test" {
  path                  = %q
  access_key            = %q
  secret_key_wo = %q
}

resource "vault_alicloud_secret_backend_role" "test_inline" {
  mount = vault_alicloud_secret_backend.test.path
  name  = "%s-inline"
  
  inline_policies = %q
  
  ttl     = 3600
  max_ttl = 7200
}

resource "vault_alicloud_secret_backend_role" "test_remote" {
  mount = vault_alicloud_secret_backend.test.path
  name  = "%s-remote"
  
  remote_policies = "name:AliyunOSSReadOnlyAccess,type:System"
  
  ttl = 1800
}

resource "vault_alicloud_secret_backend_role" "test_role_arn" {
  mount = vault_alicloud_secret_backend.test.path
  name  = "%s-role-arn"
  
  role_arn = "%s"
  
  ttl = 3600
}
`, backend, accessKey, secretKey, name, testAccAliCloudSecretBackendRoleInlinePolicy_basic, name, name, testAccAliCloudSecretBackendRoleRoleARN_basic)
}

func testAccAliCloudSecretBackendRoleConfig_updated(name, backend, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_alicloud_secret_backend" "test" {
  path                  = %q
  access_key            = %q
  secret_key_wo = %q
}

resource "vault_alicloud_secret_backend_role" "test_inline" {
  mount = vault_alicloud_secret_backend.test.path
  name  = "%s-inline"
  
  inline_policies = %q
  
  ttl     = 7200
  max_ttl = 14400
}

resource "vault_alicloud_secret_backend_role" "test_remote" {
  mount = vault_alicloud_secret_backend.test.path
  name  = "%s-remote"
  
  remote_policies = "name:AliyunECSReadOnlyAccess,type:System,name:AliyunRDSReadOnlyAccess,type:System"
  
  ttl = 3600
}

resource "vault_alicloud_secret_backend_role" "test_role_arn" {
  mount = vault_alicloud_secret_backend.test.path
  name  = "%s-role-arn"
  
  role_arn = "%s"
  
  ttl = 7200
}
`, backend, accessKey, secretKey, name, testAccAliCloudSecretBackendRoleInlinePolicy_updated, name, name, testAccAliCloudSecretBackendRoleRoleARN_updated)
}

func testAccAliCloudSecretBackendRoleConfig_remotePolicy(name, backend, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_alicloud_secret_backend" "test" {
  path                  = %q
  access_key            = %q
  secret_key_wo = %q
}

resource "vault_alicloud_secret_backend_role" "test" {
  mount = vault_alicloud_secret_backend.test.path
  name  = "%s"
  
  remote_policies = "name:AliyunOSSReadOnlyAccess,type:System,name:AliyunECSReadOnlyAccess,type:System"
  
  ttl     = 3600
  max_ttl = 7200
}
`, backend, accessKey, secretKey, name)
}

func testAccAliCloudSecretBackendRoleConfig_minimal(name, backend, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_alicloud_secret_backend" "test" {
  path                  = %q
  access_key            = %q
  secret_key_wo = %q
}

resource "vault_alicloud_secret_backend_role" "test" {
  mount = vault_alicloud_secret_backend.test.path
  name  = %q
  role_arn = %q
}
`, backend, accessKey, secretKey, name, testAccAliCloudSecretBackendRoleRoleARN_basic)
}

func testAccAliCloudSecretBackendRoleConfig_ttlOnly(name, backend, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_alicloud_secret_backend" "test" {
  path                  = %q
  access_key            = %q
  secret_key_wo = %q
}

resource "vault_alicloud_secret_backend_role" "test" {
  mount = vault_alicloud_secret_backend.test.path
  name  = %q
  role_arn = %q
  ttl      = 1800
}
`, backend, accessKey, secretKey, name, testAccAliCloudSecretBackendRoleRoleARN_basic)
}

func testAccAliCloudSecretBackendRoleConfig_maxTtlOnly(name, backend, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_alicloud_secret_backend" "test" {
  path                  = %q
  access_key            = %q
  secret_key_wo = %q
}

resource "vault_alicloud_secret_backend_role" "test" {
  mount = vault_alicloud_secret_backend.test.path
  name  = %q
  role_arn = %q
  max_ttl  = 7200
}
`, backend, accessKey, secretKey, name, testAccAliCloudSecretBackendRoleRoleARN_basic)
}

func testAccAliCloudSecretBackendRoleConfig_multipleRemotePolicies(name, backend, accessKey, secretKey string) string {
	return fmt.Sprintf(`
resource "vault_alicloud_secret_backend" "test" {
  path                  = %q
  access_key            = %q
  secret_key_wo = %q
}

resource "vault_alicloud_secret_backend_role" "test" {
  mount = vault_alicloud_secret_backend.test.path
  name  = %q
  
  remote_policies = "name:AliyunOSSReadOnlyAccess,type:System,name:AliyunECSReadOnlyAccess,type:System,name:AliyunRDSReadOnlyAccess,type:System"
  
  ttl     = 3600
  max_ttl = 7200
}
`, backend, accessKey, secretKey, name)
}

// Made with Bob
