// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccSSHSecretBackendRole(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test/ssh")
	name := acctest.RandomWithPrefix("tf-test-role")

	resourceName := "vault_ssh_secret_backend_role.test_role"

	commonCheckFuncs := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
		resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
	}

	initialCheckFuncs := append(commonCheckFuncs,
		resource.TestCheckResourceAttr(resourceName, consts.FieldAllowBareDomains, "false"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldAllowHostCertificates, "false"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldAllowSubdomains, "false"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldAllowUserCertificates, "true"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldAllowUserKeyIDs, "false"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedCriticalOptions, ""),
		resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedDomains, ""),
		resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedExtensions, ""),
		resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultExtensions+".%", "0"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultCriticalOptions+".%", "0"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedUsersTemplate, "false"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedUsers, ""),
		resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultUser, ""),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyIDFormat, ""),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyType, "ca"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedUserKeyConfig+"_lengths.%", "0"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldAlgorithmSigner, "default"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "0"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "0"),
		// 30s is the default value vault uese.
		// https://developer.hashicorp.com/vault/api-docs/secret/ssh#not_before_duration
		resource.TestCheckResourceAttr(resourceName, consts.FieldNotBeforeDuration, "30"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedDomainsTemplate, "false"),
	)

	updateCheckFuncs := append(commonCheckFuncs,
		resource.TestCheckResourceAttr(resourceName, consts.FieldAllowBareDomains, "true"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldAllowHostCertificates, "true"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldAllowSubdomains, "true"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldAllowUserCertificates, "false"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldAllowUserKeyIDs, "true"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedCriticalOptions, "foo,bar"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedDomains, "example.com,foo.com"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedExtensions, "ext1,ext2"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultExtensions+".ext1", ""),
		resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultCriticalOptions+".opt1", ""),
		resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedUsersTemplate, "true"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedUsers, "usr1,usr2"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultUser, "usr"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyIDFormat, "{{role_name}}-test"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldKeyType, "ca"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldAlgorithmSigner, "rsa-sha2-256"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "86400"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "43200"),
		// 50m (3000 seconds)
		resource.TestCheckResourceAttr(resourceName, consts.FieldNotBeforeDuration, "3000"),
		resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedDomainsTemplate, "true"),
	)

	getCheckFuncs := func(isUpdate bool) resource.TestCheckFunc {
		return func(state *terraform.State) error {
			var checks []resource.TestCheckFunc
			if isUpdate {
				checks = append(checks, updateCheckFuncs...)
			} else {
				checks = append(checks, initialCheckFuncs...)
			}

			return resource.ComposeAggregateTestCheckFunc(checks...)(state)
		}
	}

	getSteps := func(extraFields string) []resource.TestStep {
		return []resource.TestStep{
			{
				Config: testAccSSHSecretBackendRoleConfig_basic(name, backend),
				Check:  getCheckFuncs(false),
			},
			{
				Config: testAccSSHSecretBackendRoleConfig_updated(name, backend, false, extraFields),
				Check: resource.ComposeTestCheckFunc(
					getCheckFuncs(true),
				),
			},
			{
				Config: testAccSSHSecretBackendRoleConfig_updated(
					name, backend, true, extraFields),
				Check: resource.ComposeTestCheckFunc(
					getCheckFuncs(true),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedUserKeyConfig+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedUserKeyConfig+".0."+consts.FieldType, "rsa"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedUserKeyConfig+".0."+consts.FieldLengths+".#", "3"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedUserKeyConfig+".0."+consts.FieldLengths+".0", "2048"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedUserKeyConfig+".0."+consts.FieldLengths+".1", "3072"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedUserKeyConfig+".0."+consts.FieldLengths+".2", "4096"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedUserKeyConfig+".1."+consts.FieldType, "ec"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedUserKeyConfig+".1."+consts.FieldLengths+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedUserKeyConfig+".1."+consts.FieldLengths+".0", "256"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldAllowEmptyPrincipals),
		}
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
		},
		CheckDestroy: testAccSSHSecretBackendRoleCheckDestroy,
		Steps:        getSteps(""),
	})
}

func TestAccSSHSecretBackendRoleOTP_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test/ssh")
	name := acctest.RandomWithPrefix("tf-test-role")
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccSSHSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccSSHSecretBackendRoleOTPConfig_basic(name, backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", consts.FieldName, name),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", consts.FieldBackend, backend),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", consts.FieldAllowedUsers, "usr1,usr2"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", consts.FieldDefaultUser, "usr"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", consts.FieldCIDRList, "0.0.0.0/0"),
				),
			},
		},
	})
}

func TestAccSSHSecretBackendRole_template(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test/ssh")
	name := acctest.RandomWithPrefix("tf-test-role")
	resourceName := "vault_ssh_secret_backend_role.test_role"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
		},
		CheckDestroy: testAccSSHSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccSSHSecretBackendRoleConfig_template(name, backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultUser, "ssh-{{identity.entity.id}}-user"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultUserTemplate, "true"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldAllowEmptyPrincipals),
		},
	})
}

func testAccSSHSecretBackendRoleCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_ssh_secret_backend_role" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
		}

		role, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return err
		}
		if role != nil {
			return fmt.Errorf("role %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccSSHSecretBackendRoleConfig_basic(name, path string) string {
	config := fmt.Sprintf(`
resource "vault_mount" "example" {
  path = "%s"
  type = "ssh"
}

resource "vault_ssh_secret_backend_role" "test_role" {
  name                    = "%s"
  backend                 = vault_mount.example.path
  key_type                = "ca"
  allow_user_certificates = true
}

`, path, name)

	return config
}

func testAccSSHSecretBackendRoleConfig_updated(name, path string, withAllowedUserKeys bool,
	extraFields string,
) string {
	fragments := []string{
		fmt.Sprintf(`
resource "vault_mount" "example" {
  path = "%s"
  type = "ssh"
}`, path),
	}

	if withAllowedUserKeys {
		fragments = append(fragments, `
  locals {
    allowed_user_keys = [
      {
        type    = "rsa"
        lengths = [2048, 3072, 4096]
      },
      {
        type    = "ec"
        lengths = [256]
      },
    ]
  }
`)
	}
	fragments = append(fragments, fmt.Sprintf(`
resource "vault_ssh_secret_backend_role" "test_role" {
  name                     = "%s"
  backend                  = vault_mount.example.path
  allow_bare_domains       = true
  allow_host_certificates  = true
  allow_subdomains         = true
  allow_user_certificates  = false
  allow_user_key_ids       = true
  allowed_critical_options = "foo,bar"
  allowed_domains          = "example.com,foo.com"
  allowed_domains_template = true
  allowed_extensions       = "ext1,ext2"
  default_extensions       = { "ext1" = "" }
  default_critical_options = { "opt1" = "" }
  allowed_users_template   = true
  allowed_users            = "usr1,usr2"
  default_user             = "usr"
  key_id_format            = "{{role_name}}-test"
  key_type                 = "ca"
  algorithm_signer         = "rsa-sha2-256"
  max_ttl                  = "86400"
  ttl                      = "43200"
  not_before_duration      = "3000"
  %s
`, name, extraFields))

	if withAllowedUserKeys {
		fragments = append(fragments, `dynamic "allowed_user_key_config" {
			for_each = local.allowed_user_keys
			content {
				type    = allowed_user_key_config.value["type"]
				lengths = allowed_user_key_config.value["lengths"]
			}
		}
`)
	}

	config := strings.Join(fragments, "\n") + "}\n"

	return config
}

func testAccSSHSecretBackendRoleOTPConfig_basic(name, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "example" {
  path = "%s"
  type = "ssh"
}

resource "vault_ssh_secret_backend_role" "test_role" {
	name                     = "%s"
	backend                  = vault_mount.example.path
	allowed_users            = "usr1,usr2"
	default_user             = "usr"
	key_type                 = "otp"
	cidr_list                = "0.0.0.0/0"
}
`, path, name)
}

func testAccSSHSecretBackendRoleConfig_template(name, path string) string {
	config := fmt.Sprintf(`
resource "vault_mount" "example" {
  path = "%s"
  type = "ssh"
}

resource "vault_ssh_secret_backend_role" "test_role" {
  name                    = "%s"
  backend                 = vault_mount.example.path
  default_user_template   = true
  default_user            = "ssh-{{identity.entity.id}}-user"
  key_type                = "ca"
  allow_user_certificates = true
}

`, path, name)

	return config
}

// TestAccSSHSecretBackendRole_defaultExtensionsTemplate tests default_extensions_template field for CA roles
func TestAccSSHSecretBackendRole_defaultExtensionsTemplate(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test/ssh")
	roleName := acctest.RandomWithPrefix("tf-test-ca-role")
	resourceName := "vault_ssh_secret_backend_role.test_role"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccSSHSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccSSHSecretBackendRoleConfig_defaultExtensionsTemplate(roleName, backend, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, roleName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyType, "ca"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultExtensionsTemplate, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultExtensions+".permit-pty", ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultExtensions+".permit-port-forwarding", ""),
				),
			},
			{
				Config: testAccSSHSecretBackendRoleConfig_defaultExtensionsTemplate(roleName, backend, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultExtensionsTemplate, "false"),
				),
			},
			{
				Config: testAccSSHSecretBackendRoleConfig_defaultExtensionsTemplateEmpty(roleName, backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultExtensionsTemplate, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultExtensions+".%", "0"),
				),
			},
			// DiffSuppressFunc handles key_type-specific fields, so no exclusions needed
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldAllowEmptyPrincipals),
		},
	})
}

// TestAccSSHSecretBackendRole_otpFields tests exclude_cidr_list and port fields for OTP roles
func TestAccSSHSecretBackendRole_otpFields(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test/ssh")
	roleName := acctest.RandomWithPrefix("tf-test-otp-role")
	resourceName := "vault_ssh_secret_backend_role.test_role"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccSSHSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccSSHSecretBackendRoleConfig_otpFields(roleName, backend, `["192.168.1.0/24", "10.0.0.0/8"]`, 2222),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, roleName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKeyType, "otp"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExcludeCIDRList+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPort, "2222"),
				),
			},
			{
				Config: testAccSSHSecretBackendRoleConfig_otpFields(roleName, backend, `["172.16.0.0/12"]`, 2223),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldExcludeCIDRList+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPort, "2223"),
				),
			},
			{
				Config: testAccSSHSecretBackendRoleConfig_otpFieldsEmpty(roleName, backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldExcludeCIDRList+".#", "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldPort, "22"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldAllowEmptyPrincipals),
		},
	})
}

// Helper functions for test configurations

func testAccSSHSecretBackendRoleConfig_defaultExtensionsTemplate(roleName, path string, enabled bool) string {
	return fmt.Sprintf(`
resource "vault_mount" "example" {
  path = "%s"
  type = "ssh"
}

resource "vault_ssh_secret_backend_ca" "test" {
  backend              = vault_mount.example.path
  generate_signing_key = true
}

resource "vault_ssh_secret_backend_role" "test_role" {
  name                        = "%s"
  backend                     = vault_mount.example.path
  key_type                    = "ca"
  allow_user_certificates     = true
  default_extensions_template = %t
  default_extensions = {
    permit-pty             = ""
    permit-port-forwarding = ""
  }
  allowed_users = "ubuntu,admin,*"
  default_user  = "ubuntu"
}
`, path, roleName, enabled)
}

func testAccSSHSecretBackendRoleConfig_defaultExtensionsTemplateEmpty(roleName, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "example" {
  path = "%s"
  type = "ssh"
}

resource "vault_ssh_secret_backend_ca" "test" {
  backend              = vault_mount.example.path
  generate_signing_key = true
}

resource "vault_ssh_secret_backend_role" "test_role" {
  name                        = "%s"
  backend                     = vault_mount.example.path
  key_type                    = "ca"
  allow_user_certificates     = true
  default_extensions_template = true
  allowed_users               = "ubuntu,admin,*"
  default_user                = "ubuntu"
}
`, path, roleName)
}

func testAccSSHSecretBackendRoleConfig_otpFields(roleName, path, cidrList string, port int) string {
	return fmt.Sprintf(`
resource "vault_mount" "example" {
  path = "%s"
  type = "ssh"
}

resource "vault_ssh_secret_backend_role" "test_role" {
  name              = "%s"
  backend           = vault_mount.example.path
  key_type          = "otp"
  default_user      = "ubuntu"
  exclude_cidr_list = %s
  port              = %d
  allowed_users     = "ubuntu,admin,*"
}
`, path, roleName, cidrList, port)
}

func testAccSSHSecretBackendRoleConfig_otpFieldsEmpty(roleName, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "example" {
  path = "%s"
  type = "ssh"
}

resource "vault_ssh_secret_backend_role" "test_role" {
  name          = "%s"
  backend       = vault_mount.example.path
  key_type      = "otp"
  default_user  = "ubuntu"
  allowed_users = "ubuntu,admin,*"
}
`, path, roleName)
}

// TestAccSSHSecretBackendRole_extensionsTemplateAndOtpFieldsInvalid tests invalid field values
// Note: Vault's SSH secrets engine does not perform validation on port numbers at the API level.
// Vault accepts and stores any integer value for the port field,
// including values outside the valid TCP port range (1-65535) such as 99999 and -1.
// These test cases verify that the Terraform provider correctly handles this behavior by:
// 1. Successfully creating resources with out-of-range port values (matching Vault's permissive behavior)
// 2. Accurately reading back and storing the exact port values that Vault accepts
// This ensures the provider maintains fidelity with Vault's actual API behavior
func TestAccSSHSecretBackendRole_extensionsTemplateAndOtpFieldsInvalid(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test/ssh")
	otpRoleName := acctest.RandomWithPrefix("tf-test-otp-role")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccSSHSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				// Test: Invalid CIDR format - Vault validates CIDR format
				Config:      testAccSSHSecretBackendRoleConfig_invalidCIDR(otpRoleName, backend),
				ExpectError: regexp.MustCompile("invalid CIDR|failed to parse"),
			},
			{
				// Test: Port number exceeding valid TCP range (1-65535)
				// Vault accepts this without validation, so we verify it's stored correctly
				Config: testAccSSHSecretBackendRoleConfig_invalidPortHigh(otpRoleName, backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role_otp", consts.FieldPort, "99999"),
				),
			},
			{
				// Test: Negative port number
				// Vault accepts this without validation, so we verify it's stored correctly
				Config: testAccSSHSecretBackendRoleConfig_invalidPortNegative(otpRoleName, backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role_otp", consts.FieldPort, "-1"),
				),
			},
		},
	})
}

// Helper functions for invalid configurations

func testAccSSHSecretBackendRoleConfig_invalidCIDR(otpRoleName, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "example" {
  path = "%s"
  type = "ssh"
}

resource "vault_ssh_secret_backend_role" "test_role_otp" {
  name              = "%s"
  backend           = vault_mount.example.path
  key_type          = "otp"
  default_user      = "ubuntu"
  exclude_cidr_list = ["invalid-cidr-format"]
  allowed_users     = "ubuntu"
}
`, path, otpRoleName)
}

func testAccSSHSecretBackendRoleConfig_invalidPortHigh(otpRoleName, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "example" {
  path = "%s"
  type = "ssh"
}

resource "vault_ssh_secret_backend_role" "test_role_otp" {
  name          = "%s"
  backend       = vault_mount.example.path
  key_type      = "otp"
  default_user  = "ubuntu"
  port          = 99999
  allowed_users = "ubuntu"
}
`, path, otpRoleName)
}

func testAccSSHSecretBackendRoleConfig_invalidPortNegative(otpRoleName, path string) string {
	return fmt.Sprintf(`
resource "vault_mount" "example" {
  path = "%s"
  type = "ssh"
}

resource "vault_ssh_secret_backend_role" "test_role_otp" {
  name          = "%s"
  backend       = vault_mount.example.path
  key_type      = "otp"
  default_user  = "ubuntu"
  port          = -1
  allowed_users = "ubuntu"
}
`, path, otpRoleName)
}
