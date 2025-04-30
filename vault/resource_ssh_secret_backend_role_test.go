// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccSSHSecretBackendRole(t *testing.T) {
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("tf-test/ssh")
	name := acctest.RandomWithPrefix("tf-test-role")

	resourceName := "vault_ssh_secret_backend_role.test_role"

	commonCheckFuncs := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, "name", name),
		resource.TestCheckResourceAttr(resourceName, "backend", backend),
	}

	initialCheckFuncs := append(commonCheckFuncs,
		resource.TestCheckResourceAttr(resourceName, "allow_bare_domains", "false"),
		resource.TestCheckResourceAttr(resourceName, "allow_host_certificates", "false"),
		resource.TestCheckResourceAttr(resourceName, "allow_subdomains", "false"),
		resource.TestCheckResourceAttr(resourceName, "allow_user_certificates", "true"),
		resource.TestCheckResourceAttr(resourceName, "allow_user_key_ids", "false"),
		resource.TestCheckResourceAttr(resourceName, "allowed_critical_options", ""),
		resource.TestCheckResourceAttr(resourceName, "allowed_domains", ""),
		resource.TestCheckResourceAttr(resourceName, "allowed_extensions", ""),
		resource.TestCheckResourceAttr(resourceName, "default_extensions.%", "0"),
		resource.TestCheckResourceAttr(resourceName, "default_critical_options.%", "0"),
		resource.TestCheckResourceAttr(resourceName, "allowed_users_template", "false"),
		resource.TestCheckResourceAttr(resourceName, "allowed_users", ""),
		resource.TestCheckResourceAttr(resourceName, "default_user", ""),
		resource.TestCheckResourceAttr(resourceName, "key_id_format", ""),
		resource.TestCheckResourceAttr(resourceName, "key_type", "ca"),
		resource.TestCheckResourceAttr(resourceName, "allowed_user_key_config_lengths.%", "0"),
		resource.TestCheckResourceAttr(resourceName, "algorithm_signer", "default"),
		resource.TestCheckResourceAttr(resourceName, "max_ttl", "0"),
		resource.TestCheckResourceAttr(resourceName, "ttl", "0"),
		// 30s is the default value vault uese.
		// https://developer.hashicorp.com/vault/api-docs/secret/ssh#not_before_duration
		resource.TestCheckResourceAttr(resourceName, "not_before_duration", "30"),
		resource.TestCheckResourceAttr(resourceName, "allowed_domains_template", "false"),
	)

	updateCheckFuncs := append(commonCheckFuncs,
		resource.TestCheckResourceAttr(resourceName, "allow_bare_domains", "true"),
		resource.TestCheckResourceAttr(resourceName, "allow_host_certificates", "true"),
		resource.TestCheckResourceAttr(resourceName, "allow_subdomains", "true"),
		resource.TestCheckResourceAttr(resourceName, "allow_user_certificates", "false"),
		resource.TestCheckResourceAttr(resourceName, "allow_user_key_ids", "true"),
		resource.TestCheckResourceAttr(resourceName, "allowed_critical_options", "foo,bar"),
		resource.TestCheckResourceAttr(resourceName, "allowed_domains", "example.com,foo.com"),
		resource.TestCheckResourceAttr(resourceName, "allowed_extensions", "ext1,ext2"),
		resource.TestCheckResourceAttr(resourceName, "default_extensions.ext1", ""),
		resource.TestCheckResourceAttr(resourceName, "default_critical_options.opt1", ""),
		resource.TestCheckResourceAttr(resourceName, "allowed_users_template", "true"),
		resource.TestCheckResourceAttr(resourceName, "allowed_users", "usr1,usr2"),
		resource.TestCheckResourceAttr(resourceName, "default_user", "usr"),
		resource.TestCheckResourceAttr(resourceName, "key_id_format", "{{role_name}}-test"),
		resource.TestCheckResourceAttr(resourceName, "key_type", "ca"),
		resource.TestCheckResourceAttr(resourceName, "algorithm_signer", "rsa-sha2-256"),
		resource.TestCheckResourceAttr(resourceName, "max_ttl", "86400"),
		resource.TestCheckResourceAttr(resourceName, "ttl", "43200"),
		// 50m (3000 seconds)
		resource.TestCheckResourceAttr(resourceName, "not_before_duration", "3000"),
		resource.TestCheckResourceAttr(resourceName, "allowed_domains_template", "true"),
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
					resource.TestCheckResourceAttr(resourceName, "allowed_user_key_config.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "allowed_user_key_config.0.type", "rsa"),
					resource.TestCheckResourceAttr(resourceName, "allowed_user_key_config.0.lengths.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "allowed_user_key_config.0.lengths.0", "2048"),
					resource.TestCheckResourceAttr(resourceName, "allowed_user_key_config.0.lengths.1", "3072"),
					resource.TestCheckResourceAttr(resourceName, "allowed_user_key_config.0.lengths.2", "4096"),
					resource.TestCheckResourceAttr(resourceName, "allowed_user_key_config.1.type", "ec"),
					resource.TestCheckResourceAttr(resourceName, "allowed_user_key_config.1.lengths.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "allowed_user_key_config.1.lengths.0", "256"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "allow_empty_principals"),
		}
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
		},
		CheckDestroy: testAccSSHSecretBackendRoleCheckDestroy,
		Steps:        getSteps(""),
	})
}

func TestAccSSHSecretBackendRoleOTP_basic(t *testing.T) {
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("tf-test/ssh")
	name := acctest.RandomWithPrefix("tf-test-role")
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testAccSSHSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccSSHSecretBackendRoleOTPConfig_basic(name, backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "name", name),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "backend", backend),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "allowed_users", "usr1,usr2"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "default_user", "usr"),
					resource.TestCheckResourceAttr("vault_ssh_secret_backend_role.test_role", "cidr_list", "0.0.0.0/0"),
				),
			},
		},
	})
}

func TestAccSSHSecretBackendRole_template(t *testing.T) {
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("tf-test/ssh")
	name := acctest.RandomWithPrefix("tf-test-role")
	resourceName := "vault_ssh_secret_backend_role.test_role"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion112)
		},
		CheckDestroy: testAccSSHSecretBackendRoleCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccSSHSecretBackendRoleConfig_template(name, backend),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "default_user", "ssh-{{identity.entity.id}}-user"),
					resource.TestCheckResourceAttr(resourceName, "default_user_template", "true"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "allow_empty_principals"),
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
