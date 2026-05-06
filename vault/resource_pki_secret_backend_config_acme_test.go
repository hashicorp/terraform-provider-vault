// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestPkiSecretBackendConfigACME_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("pki-root")
	resourceType := "vault_pki_secret_backend_config_acme"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion114)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypePKI, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendConfigACME(backend, "sign-verbatim", "*", "*", "not-required", "",
					false, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnabled, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultDirectoryPolicy, "sign-verbatim"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedRoles+".0", "*"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIssuers+".0", "*"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEabPolicy, "not-required"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDnsResolver, ""),
				),
			},
			{
				Config: testPkiSecretBackendConfigACME(backend, "forbid", "test", "*", "new-account-required",
					"1.1.1.1:8443", true, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultDirectoryPolicy, "forbid"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedRoles+".0", "test"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIssuers+".0", "*"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEabPolicy, "new-account-required"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDnsResolver, "1.1.1.1:8443"),
				),
			},
			{
				Config: testPkiSecretBackendConfigACME(backend, "role:test", "*", "*", "always-required", "",
					true, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultDirectoryPolicy, "role:test"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedRoles+".0", "*"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowRoleExtKeyUsage, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIssuers+".0", "*"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEabPolicy, "always-required"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDnsResolver, ""),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion117)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypePKI, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendConfigACME_v117(backend, "sign-verbatim", "*", "*", "not-required", "",
					true, false, 7776000),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultDirectoryPolicy, "sign-verbatim"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedRoles+".0", "*"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIssuers+".0", "*"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEabPolicy, "not-required"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDnsResolver, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "7776000"),
				),
			},
			{
				Config: testPkiSecretBackendConfigACME_v117(backend, "role:test", "*", "*", "always-required", "",
					true, true, 3600),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultDirectoryPolicy, "role:test"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedRoles+".0", "*"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowRoleExtKeyUsage, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIssuers+".0", "*"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEabPolicy, "always-required"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDnsResolver, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "3600"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

func TestPkiSecretBackendConfigACME_WithChallengeParams(t *testing.T) {
	backend := acctest.RandomWithPrefix("pki-root")
	resourceType := "vault_pki_secret_backend_config_acme"
	resourceName := resourceType + ".test"

	// Test for challenge IP range fields (Vault 1.19.16+, 1.20.10+, 1.21.5+)
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion1215)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypePKI, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendConfigACME_WithChallengeIpRanges(backend, "sign-verbatim", "*", "*", "not-required", "",
					true, false, 7776000, []string{"10.0.0.0/8", "192.168.0.0/16"}, []string{"10.1.0.0/16"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultDirectoryPolicy, "sign-verbatim"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedRoles+".0", "*"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIssuers+".0", "*"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEabPolicy, "not-required"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDnsResolver, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "7776000"),
					resource.TestCheckResourceAttr(resourceName, FieldChallengePermittedIPRanges+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, FieldChallengePermittedIPRanges+".0", "10.0.0.0/8"),
					resource.TestCheckResourceAttr(resourceName, FieldChallengePermittedIPRanges+".1", "192.168.0.0/16"),
					resource.TestCheckResourceAttr(resourceName, FieldChallengeExcludedIPRanges+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, FieldChallengeExcludedIPRanges+".0", "10.1.0.0/16"),
				),
			},
			{
				Config: testPkiSecretBackendConfigACME_WithChallengeIpRanges(backend, "role:test", "*", "*", "always-required", "",
					true, true, 3600, []string{"172.16.0.0/12"}, []string{"172.16.1.0/24", "172.16.2.0/24"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultDirectoryPolicy, "role:test"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedRoles+".0", "*"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowRoleExtKeyUsage, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIssuers+".0", "*"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEabPolicy, "always-required"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDnsResolver, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "3600"),
					resource.TestCheckResourceAttr(resourceName, FieldChallengePermittedIPRanges+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, FieldChallengePermittedIPRanges+".0", "172.16.0.0/12"),
					resource.TestCheckResourceAttr(resourceName, FieldChallengeExcludedIPRanges+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, FieldChallengeExcludedIPRanges+".0", "172.16.1.0/24"),
					resource.TestCheckResourceAttr(resourceName, FieldChallengeExcludedIPRanges+".1", "172.16.2.0/24"),
				),
			},
			{
				Config: testPkiSecretBackendConfigACME_WithChallengeIpRanges(backend, "forbid", "test", "*", "new-account-required",
					"1.1.1.1:8443", true, false, 86400, []string{}, []string{}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnabled, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultDirectoryPolicy, "forbid"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedRoles+".0", "test"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIssuers+".0", "*"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEabPolicy, "new-account-required"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDnsResolver, "1.1.1.1:8443"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "86400"),
					resource.TestCheckResourceAttr(resourceName, FieldChallengePermittedIPRanges+".#", "0"),
					resource.TestCheckResourceAttr(resourceName, FieldChallengeExcludedIPRanges+".#", "0"),
				),
			},
		},
	})
}

func testPkiSecretBackendConfigACME(path, default_directory_policy, allowed_roles, allowed_issuers,
	eab_policy, dns_resolver string, enabled, allow_role_ext_key_usage bool) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "pki"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend     = vault_mount.test.path
  type        = "internal"
  common_name = "test"
  ttl         = "86400"
}

resource "vault_pki_secret_backend_config_cluster" "test" {
  backend  = vault_mount.test.path
  path     = "http://127.0.0.1:8200/v1/${vault_mount.test.path}"
  aia_path = "http://127.0.0.1:8200/v1/${vault_mount.test.path}"
}

resource "vault_pki_secret_backend_role" "test" {
  backend = vault_pki_secret_backend_root_cert.test.backend
  name    = "test"
}

resource "vault_pki_secret_backend_config_acme" "test" {
  backend                  = vault_mount.test.path
  enabled                  = "%t"
  allowed_issuers          = ["%s"]
  allowed_roles            = ["%s"]
  allow_role_ext_key_usage = "%t"
  default_directory_policy = "%s"
  dns_resolver             = "%s"
  eab_policy               = "%s"
}`, path, enabled, allowed_issuers, allowed_roles, allow_role_ext_key_usage,
		default_directory_policy, dns_resolver, eab_policy)
}

func testPkiSecretBackendConfigACME_v117(path, default_directory_policy, allowed_roles, allowed_issuers,
	eab_policy, dns_resolver string, enabled, allow_role_ext_key_usage bool, max_ttl int) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "pki"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend     = vault_mount.test.path
  type        = "internal"
  common_name = "test"
  ttl         = "86400"
}

resource "vault_pki_secret_backend_config_cluster" "test" {
  backend  = vault_mount.test.path
  path     = "http://127.0.0.1:8200/v1/${vault_mount.test.path}"
  aia_path = "http://127.0.0.1:8200/v1/${vault_mount.test.path}"
}

resource "vault_pki_secret_backend_role" "test" {
  backend = vault_pki_secret_backend_root_cert.test.backend
  name    = "test"
}

resource "vault_pki_secret_backend_config_acme" "test" {
  backend                  = vault_mount.test.path
  enabled                  = "%t"
  allowed_issuers          = ["%s"]
  allowed_roles            = ["%s"]
  allow_role_ext_key_usage = "%t"
  default_directory_policy = "%s"
  dns_resolver             = "%s"
  eab_policy               = "%s"
  max_ttl                  = "%d"
}`, path, enabled, allowed_issuers, allowed_roles, allow_role_ext_key_usage,
		default_directory_policy, dns_resolver, eab_policy, max_ttl)
}

func testPkiSecretBackendConfigACME_WithChallengeIpRanges(path, default_directory_policy, allowed_roles, allowed_issuers,
	eab_policy, dns_resolver string, enabled, allow_role_ext_key_usage bool, max_ttl int,
	challenge_permitted_ip_ranges, challenge_excluded_ip_ranges []string) string {

	permittedIPRangesStr := ""
	if len(challenge_permitted_ip_ranges) > 0 {
		permittedIPRangesStr = "challenge_permitted_ip_ranges = ["
		for i, ip := range challenge_permitted_ip_ranges {
			if i > 0 {
				permittedIPRangesStr += ", "
			}
			permittedIPRangesStr += fmt.Sprintf(`"%s"`, ip)
		}
		permittedIPRangesStr += "]\n"
	}

	excludedIPRangesStr := ""
	if len(challenge_excluded_ip_ranges) > 0 {
		excludedIPRangesStr = "challenge_excluded_ip_ranges = ["
		for i, ip := range challenge_excluded_ip_ranges {
			if i > 0 {
				excludedIPRangesStr += ", "
			}
			excludedIPRangesStr += fmt.Sprintf(`"%s"`, ip)
		}
		excludedIPRangesStr += "]\n"
	}

	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "pki"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend     = vault_mount.test.path
  type        = "internal"
  common_name = "test"
  ttl         = "86400"
}

resource "vault_pki_secret_backend_config_cluster" "test" {
  backend  = vault_mount.test.path
  path     = "http://127.0.0.1:8200/v1/${vault_mount.test.path}"
  aia_path = "http://127.0.0.1:8200/v1/${vault_mount.test.path}"
}

resource "vault_pki_secret_backend_role" "test" {
  backend = vault_pki_secret_backend_root_cert.test.backend
  name    = "test"
}

resource "vault_pki_secret_backend_config_acme" "test" {
  backend                  = vault_mount.test.path
  enabled                  = "%t"
  allowed_issuers          = ["%s"]
  allowed_roles            = ["%s"]
  allow_role_ext_key_usage = "%t"
  default_directory_policy = "%s"
  dns_resolver             = "%s"
  eab_policy               = "%s"
  max_ttl                  = "%d"
  %s%s}`, path, enabled, allowed_issuers, allowed_roles, allow_role_ext_key_usage,
		default_directory_policy, dns_resolver, eab_policy, max_ttl,
		permittedIPRangesStr, excludedIPRangesStr)
}
