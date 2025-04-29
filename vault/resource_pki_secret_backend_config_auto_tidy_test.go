// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/stretchr/testify/require"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestPkiSecretBackendConfigAutoTidySuppressDurationDiff(t *testing.T) {
	var p *schema.Provider
	type testCase struct {
		oldValue string
		newValue string
		expected bool
	}
	same := func(oldValue, newValue string) testCase {
		return testCase{oldValue, newValue, true}
	}
	diff := func(oldValue, newValue string) testCase {
		return testCase{oldValue, newValue, false}
	}
	testCases := []testCase{
		diff("", "1"),
		diff("1", ""),
		same("1", "1s"),
		same("1", "0h0m1s"),
		diff("1s", "2s"),
		same("60", "1m"),
		same("3600", "1h"),
		same("61", "1m1s"),
	}
	for _, tc := range testCases {
		require.Equal(t, tc.expected,
			pkiSecretBackendConfigAutoTidySuppressDurationDiff("interval_duration", tc.oldValue, tc.newValue, nil),
			"test case %v", tc)
	}
}

func TestAccPKISecretBackendConfigAutoTidy_basic(t *testing.T) {
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("tf-test-pki")
	resourceType := "vault_pki_secret_backend_config_auto_tidy"
	resourceName := resourceType + ".test"

	checkAttributes := func(expected string, fields ...string) resource.TestCheckFunc {
		return func(s *terraform.State) error {
			meta := testProvider.Meta().(*provider.ProviderMeta)
			var checks []resource.TestCheckFunc
			for _, f := range fields {
				switch {
				case f == consts.FieldTidyCertMetadata && !meta.IsAPISupported(provider.VaultVersion117):
				case f == consts.FieldTidyCmpv2NonceStore && !meta.IsAPISupported(provider.VaultVersion118):
				case f == consts.FieldMaxStartupBackoffDuration && !meta.IsAPISupported(provider.VaultVersion118):
				case f == consts.FieldMinStartupBackoffDuration && !meta.IsAPISupported(provider.VaultVersion118):
				default:
					checks = append(checks, resource.TestCheckResourceAttr(resourceName, f, expected))
				}
			}
			return resource.ComposeTestCheckFunc(checks...)(s)
		}
	}

	getImportTestStep := func(minVer *version.Version, ignoreFields ...string) resource.TestStep {
		ret := testutil.GetImportTestStep(resourceName, false, nil, ignoreFields...)
		if minVer != nil {
			ret.SkipFunc = func() (bool, error) {
				meta := testProvider.Meta().(*provider.ProviderMeta)
				return !meta.IsAPISupported(minVer), nil
			}
		}
		return ret
	}

	allAttributesSetCheck := func(s *terraform.State) error {
		meta := testProvider.Meta().(*provider.ProviderMeta)
		for field := range pkiSecretBackendConfigAutoTidySchema() {
			switch {
			case field == consts.FieldTidyCertMetadata && !meta.IsAPISupported(provider.VaultVersion117):
			case field == consts.FieldTidyCmpv2NonceStore && !meta.IsAPISupported(provider.VaultVersion118):
			case field == consts.FieldMaxStartupBackoffDuration && !meta.IsAPISupported(provider.VaultVersion118):
			case field == consts.FieldMinStartupBackoffDuration && !meta.IsAPISupported(provider.VaultVersion118):
			default:
				err := resource.TestCheckResourceAttrSet(resourceName, field)(s)
				if err != nil {
					return err
				}
			}
		}
		return nil
	}
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypePKI, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config:      testAccPKISecretBackendConfigAutoTidy_basic(backend, `enabled = true`),
				ExpectError: regexp.MustCompile("Missing required argument"),
			},
			{
				// Simplest call with enabled = false
				Config: testAccPKISecretBackendConfigAutoTidy_basic(backend, `
enabled = false
tidy_cert_store = true
`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					checkAttributes("false", consts.FieldEnabled),
					checkAttributes("true", consts.FieldTidyCertStore),
					allAttributesSetCheck,
				),
			},
			{
				// Enable a couple of tidy operations
				Config: testAccPKISecretBackendConfigAutoTidy_basic(backend, `
enabled = true
tidy_cert_store = true
tidy_acme = true
`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					checkAttributes("true",
						consts.FieldEnabled,
						consts.FieldTidyCertStore,
						consts.FieldTidyAcme),
					checkAttributes("false",
						consts.FieldTidyRevokedCerts,
						consts.FieldTidyRevokedCertIssuerAssociations,
						consts.FieldTidyExpiredIssuers,
						consts.FieldTidyMoveLegacyCaBundle,
						consts.FieldTidyRevocationQueue,
						consts.FieldTidyCrossClusterRevokedCerts,
						consts.FieldTidyCertMetadata,
						consts.FieldTidyCmpv2NonceStore,
					),
				),
			},
			{
				// Enable all tidy operations (minus the ENT ones: tidy_cert_metadata and tidy_cmpv2_nonce_store)
				Config: testAccPKISecretBackendConfigAutoTidy_basic(backend, `
enabled = true
tidy_cert_store = true
tidy_revoked_certs = true
tidy_revoked_cert_issuer_associations = true
tidy_expired_issuers = true
tidy_move_legacy_ca_bundle = true
tidy_acme = true
tidy_revocation_queue = true
tidy_cross_cluster_revoked_certs = true
`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					checkAttributes("true",
						consts.FieldEnabled,
						consts.FieldTidyCertStore,
						consts.FieldTidyRevokedCerts,
						consts.FieldTidyRevokedCertIssuerAssociations,
						consts.FieldTidyExpiredIssuers,
						consts.FieldTidyMoveLegacyCaBundle,
						consts.FieldTidyAcme,
						consts.FieldTidyRevocationQueue,
						consts.FieldTidyCrossClusterRevokedCerts,
					),
				),
			},
			{
				// Set a duration attribute
				Config: testAccPKISecretBackendConfigAutoTidy_basic(backend, `
enabled = true
tidy_cert_store = true
interval_duration = "123s"
`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					checkAttributes("true",
						consts.FieldEnabled,
						consts.FieldTidyCertStore),
					checkAttributes("123", consts.FieldIntervalDuration),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
			{
				// Change a duration attribute
				Config: testAccPKISecretBackendConfigAutoTidy_basic(backend, `
enabled = true
tidy_cert_store = true
interval_duration = "3m"
`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					checkAttributes("true",
						consts.FieldEnabled,
						consts.FieldTidyCertStore),
					checkAttributes("180", consts.FieldIntervalDuration),
				),
			},
			{
				// Set the non-tidy bool fields
				Config: testAccPKISecretBackendConfigAutoTidy_basic(backend, `
enabled = true
tidy_acme = true
maintain_stored_certificate_counts = true
publish_stored_certificate_count_metrics = true
`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					checkAttributes("true",
						consts.FieldEnabled,
						consts.FieldTidyAcme,
						consts.FieldMaintainStoredCertificateCounts,
						consts.FieldPublishStoredCertificateCountMetrics),
				),
			},
			{
				// Set all the duration fields, pre 1.18 (no min/max startup backoff duration)
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return meta.GetVaultVersion().LessThan(provider.VaultVersion118), nil
				},
				Config: testAccPKISecretBackendConfigAutoTidy_basic(backend, `
enabled = true
tidy_acme = true
acme_account_safety_buffer = "10000s"
issuer_safety_buffer = "12000s"
pause_duration = "4m2s"
revocation_queue_safety_buffer = "2800s"
safety_buffer = "59000s"
`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					checkAttributes("true",
						consts.FieldEnabled,
						consts.FieldTidyAcme,
					),
					checkAttributes("10000", consts.FieldAcmeAccountSafetyBuffer),
					checkAttributes("12000", consts.FieldIssuerSafetyBuffer),
					checkAttributes("4m2s", consts.FieldPauseDuration), // Interesting, pause_duration behaves correctly
					checkAttributes("2800", consts.FieldRevocationQueueSafetyBuffer),
					checkAttributes("59000", consts.FieldSafetyBuffer),
				),
			},
			{
				// Set all the duration fields 1.18+
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return meta.GetVaultVersion().GreaterThanOrEqual(provider.VaultVersion118), nil
				},
				Config: testAccPKISecretBackendConfigAutoTidy_basic(backend, `
enabled = true
tidy_acme = true
acme_account_safety_buffer = "10000s"
issuer_safety_buffer = "12000s"
max_startup_backoff_duration = "15000s"
min_startup_backoff_duration = "1000s"
pause_duration = "4m2s"
revocation_queue_safety_buffer = "2800s"
safety_buffer = "59000s"
`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					checkAttributes("true",
						consts.FieldEnabled,
						consts.FieldTidyAcme,
					),
					checkAttributes("10000", consts.FieldAcmeAccountSafetyBuffer),
					checkAttributes("12000", consts.FieldIssuerSafetyBuffer),
					checkAttributes("15000", consts.FieldMaxStartupBackoffDuration),
					checkAttributes("1000", consts.FieldMinStartupBackoffDuration),
					checkAttributes("4m2s", consts.FieldPauseDuration), // Interesting, pause_duration behaves correctly
					checkAttributes("2800", consts.FieldRevocationQueueSafetyBuffer),
					checkAttributes("59000", consts.FieldSafetyBuffer),
				),
			},
			{
				// This is the example in the documentation
				Config: testAccPKISecretBackendConfigAutoTidy_basic(backend, `
  enabled = true
  tidy_cert_store = true
  interval_duration = "1h"
`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					checkAttributes("true",
						consts.FieldEnabled,
						consts.FieldTidyCertStore,
					),
					checkAttributes("3600", consts.FieldIntervalDuration),
				),
			},
			getImportTestStep(provider.VaultVersion118),
			getImportTestStep(provider.VaultVersion117, consts.FieldTidyCmpv2NonceStore, consts.FieldMinStartupBackoffDuration, consts.FieldMaxStartupBackoffDuration),
			getImportTestStep(nil, consts.FieldTidyCertMetadata, consts.FieldTidyCmpv2NonceStore, consts.FieldMinStartupBackoffDuration, consts.FieldMaxStartupBackoffDuration),
		},
	})
}

func TestAccPKISecretBackendConfigAutoTidy_ent(t *testing.T) {
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("tf-test-pki")
	resourceType := "vault_pki_secret_backend_config_auto_tidy"
	resourceName := resourceType + ".test"

	checkAttributes := func(expected string, fields ...string) resource.TestCheckFunc {
		var checks []resource.TestCheckFunc
		for _, f := range fields {
			checks = append(checks, resource.TestCheckResourceAttr(resourceName, f, expected))
		}
		return resource.ComposeTestCheckFunc(checks...)
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion117)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypePKI, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				// Enable all tidy operations
				Config: testAccPKISecretBackendConfigAutoTidy_basic(backend, `
enabled = true
tidy_cert_store = true
tidy_revoked_certs = true
tidy_revoked_cert_issuer_associations = true
tidy_expired_issuers = true
tidy_move_legacy_ca_bundle = true
tidy_acme = true
tidy_revocation_queue = true
tidy_cross_cluster_revoked_certs = true
tidy_cert_metadata = true
# tidy_cmpv2_nonce_store = true # TODO: Enable once VAULT-34539 is fixed 
`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					checkAttributes("true",
						consts.FieldEnabled,
						consts.FieldTidyCertStore,
						consts.FieldTidyRevokedCerts,
						consts.FieldTidyRevokedCertIssuerAssociations,
						consts.FieldTidyExpiredIssuers,
						consts.FieldTidyMoveLegacyCaBundle,
						consts.FieldTidyAcme,
						consts.FieldTidyRevocationQueue,
						consts.FieldTidyCrossClusterRevokedCerts,
						consts.FieldTidyCertMetadata,
						// consts.FieldTidyCmpv2NonceStore, // TODO: Enable once VAULT-34539 is fixed (and set min req version)
					),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})

}

func testAccPKISecretBackendConfigAutoTidy_basic(path, fields string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path        = "%s"
	type        = "pki"
    description = "PKI secret engine mount"
}

resource "vault_pki_secret_backend_config_auto_tidy" "test" {
  backend = vault_mount.test.path
  %s
}`, path, fields)
}
