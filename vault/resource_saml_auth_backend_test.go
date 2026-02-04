// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccSAMLAuthBackend_basic(t *testing.T) {
	path := acctest.RandomWithPrefix("saml")
	resourceType := "vault_saml_auth_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeSAML, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccSAMLAuthBackendConfig_basic(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName,
						consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName,
						consts.FieldIDPMetadataURL, "https://company.okta.com/app/abc123eb9xnIfzlaf697/sso/saml/metadata"),
					resource.TestCheckResourceAttr(resourceName,
						consts.FieldEntityID, "https://my.vault/v1/auth/saml"),
					resource.TestCheckResourceAttr(resourceName,
						"acs_urls.#", "1"),
					resource.TestCheckResourceAttr(resourceName,
						"acs_urls.0", "https://my.vault.primary/v1/auth/saml/callback"),
					resource.TestCheckResourceAttr(resourceName,
						consts.FieldDefaultRole, "admin"),
				),
			},
			{
				Config: testAccSAMLAuthBackendConfig_updated(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName,
						consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName,
						consts.FieldIDPMetadataURL, "https://company.okta.com/app/abc123eb9xnIfzlaf697/sso/saml/metadata"),
					resource.TestCheckResourceAttr(resourceName,
						consts.FieldEntityID, "https://my.vault/v1/auth/saml"),
					resource.TestCheckResourceAttr(resourceName,
						"acs_urls.#", "2"),
					resource.TestCheckResourceAttr(resourceName,
						"acs_urls.0", "https://my.vault.primary/v1/auth/saml/callback"),
					resource.TestCheckResourceAttr(resourceName,
						"acs_urls.1", "https://my.vault.secondary/v1/auth/saml/callback"),
					resource.TestCheckResourceAttr(resourceName,
						consts.FieldDefaultRole, "project-aqua-developers"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldDisableRemount),
		},
	})
}

func testAccSAMLAuthBackendConfig_basic(path string) string {
	ret := fmt.Sprintf(`
resource "vault_saml_auth_backend" "test" {
  path             = "%s"
  idp_metadata_url = "https://company.okta.com/app/abc123eb9xnIfzlaf697/sso/saml/metadata"
  entity_id        = "https://my.vault/v1/auth/saml"
  acs_urls         = ["https://my.vault.primary/v1/auth/saml/callback"]
  default_role     = "admin"
}
`, path)
	return ret
}

func testAccSAMLAuthBackendConfig_updated(path string) string {
	ret := fmt.Sprintf(`
resource "vault_saml_auth_backend" "test" {
  path             = "%s"
  idp_metadata_url = "https://company.okta.com/app/abc123eb9xnIfzlaf697/sso/saml/metadata"
  entity_id        = "https://my.vault/v1/auth/saml"
  acs_urls         = ["https://my.vault.primary/v1/auth/saml/callback", "https://my.vault.secondary/v1/auth/saml/callback"]
  default_role     = "project-aqua-developers"
}
`, path)
	return ret
}

func TestAccSAMLAuthBackend_tune(t *testing.T) {
	path := acctest.RandomWithPrefix("saml-tune")
	resourceType := "vault_saml_auth_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeSAML, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccSAMLAuthBackendConfig_tuning(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tune.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.default_lease_ttl", "2m"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.max_lease_ttl", "5m"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.listing_visibility", "unauth"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.token_type", "default-batch"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_request_keys.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_request_keys.0", "key1"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_request_keys.1", "key2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_response_keys.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_response_keys.0", "key3"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_response_keys.1", "key4"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.0", "X-Custom-Header"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.1", "X-Forwarded-To"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.0", "X-Custom-Response-Header"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.1", "X-Forwarded-Response-To"),
				),
			},
			{
				Config: testAccSAMLAuthBackendConfig_tuneUpdated(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "tune.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.default_lease_ttl", "3m"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.max_lease_ttl", "6m"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.listing_visibility", "hidden"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.token_type", "service"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_request_keys.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.audit_non_hmac_response_keys.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.passthrough_request_headers.#", "0"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.allowed_response_headers.#", "0"),
				),
			},
		},
	})
}

func testAccSAMLAuthBackendConfig_tuning(path string) string {
	return fmt.Sprintf(`
resource "vault_saml_auth_backend" "test" {
  path             = "%s"
  idp_metadata_url = "https://company.okta.com/app/abc123eb9xnIfzlaf697/sso/saml/metadata"
  entity_id        = "https://my.vault/v1/auth/saml"
  acs_urls         = ["https://my.vault.primary/v1/auth/saml/callback"]
  default_role     = "admin"
  tune {
    default_lease_ttl  = "2m"
    max_lease_ttl      = "5m"
    listing_visibility = "unauth"
    token_type         = "default-batch"
	audit_non_hmac_request_keys = ["key1", "key2"]
	audit_non_hmac_response_keys = ["key3", "key4"]
	passthrough_request_headers = ["X-Custom-Header", "X-Forwarded-To"]
	allowed_response_headers = ["X-Custom-Response-Header", "X-Forwarded-Response-To"]
  }
}
`, path)
}

func testAccSAMLAuthBackendConfig_tuneUpdated(path string) string {
	return fmt.Sprintf(`
resource "vault_saml_auth_backend" "test" {
  path             = "%s"
  idp_metadata_url = "https://company.okta.com/app/abc123eb9xnIfzlaf697/sso/saml/metadata"
  entity_id        = "https://my.vault/v1/auth/saml"
  acs_urls         = ["https://my.vault.primary/v1/auth/saml/callback"]
  default_role     = "admin"
  tune {
    default_lease_ttl  = "3m"
    max_lease_ttl      = "6m"
    listing_visibility = "hidden"
    token_type         = "service"
  }
}
`, path)
}

func TestAccSAMLAuthBackend_importTune(t *testing.T) {
	path := acctest.RandomWithPrefix("saml-import-tune")
	resourceType := "vault_saml_auth_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion115)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeSAML, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccSAMLAuthBackendConfig_tuning(path),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldDisableRemount),
		},
	})
}

func TestAccSAMLAuthBackend_booleanFlags(t *testing.T) {
	path := acctest.RandomWithPrefix("saml-bool")
	resourceType := "vault_saml_auth_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeSAML, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccSAMLAuthBackendConfig_booleansDefault(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldVerboseLogging, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValidateAssertionSignature, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValidateResponseSignature, "false"),
				),
			},
			{
				Config: testAccSAMLAuthBackendConfig_booleansExplicit(path, true, true, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldVerboseLogging, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValidateAssertionSignature, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValidateResponseSignature, "false"),
				),
			},
			{
				Config: testAccSAMLAuthBackendConfig_booleansDefault(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldVerboseLogging, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValidateAssertionSignature, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValidateResponseSignature, "false"),
				),
			},
		},
	})
}

func testAccSAMLAuthBackendConfig_booleansDefault(path string) string {
	return fmt.Sprintf(`
resource "vault_saml_auth_backend" "test" {
  path             = "%s"
  idp_metadata_url = "https://company.okta.com/app/abc123eb9xnIfzlaf697/sso/saml/metadata"
  entity_id        = "https://my.vault/v1/auth/saml"
  acs_urls         = ["https://my.vault/v1/auth/saml/callback"]
}
`, path)
}

func testAccSAMLAuthBackendConfig_booleansExplicit(path string, verbose, validateAssertionSignature, validateResponseSignature bool) string {
	return fmt.Sprintf(`
resource "vault_saml_auth_backend" "test" {
  path                         = "%s"
  idp_metadata_url             = "https://company.okta.com/app/abc123eb9xnIfzlaf697/sso/saml/metadata"
  entity_id                    = "https://my.vault/v1/auth/saml"
  acs_urls                     = ["https://my.vault/v1/auth/saml/callback"]
  verbose_logging              = %t
  validate_assertion_signature = %t
  validate_response_signature  = %t
}
`, path, verbose, validateAssertionSignature, validateResponseSignature)
}

func TestAccSAMLAuthBackend_fullConfig(t *testing.T) {
	path := acctest.RandomWithPrefix("saml-full")
	resourceType := "vault_saml_auth_backend"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion119)
		},
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeSAML, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testAccSAMLAuthBackendConfig_full(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldIDPMetadataURL, "https://company.okta.com/app/abc123eb9xnIfzlaf697/sso/saml/metadata"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEntityID, "https://my.vault/v1/auth/saml"),
					resource.TestCheckResourceAttr(resourceName, "acs_urls.#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultRole, "default"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldVerboseLogging, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValidateAssertionSignature, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldValidateResponseSignature, "false"),
					resource.TestCheckResourceAttr(resourceName, "tune.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.default_lease_ttl", "10m"),
					resource.TestCheckResourceAttr(resourceName, "tune.0.max_lease_ttl", "20m"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldDisableRemount, "tune.0.token_type"),
		},
	})
}

func testAccSAMLAuthBackendConfig_full(path string) string {
	return fmt.Sprintf(`
resource "vault_saml_auth_backend" "test" {
  path                         = "%s"
  idp_metadata_url             = "https://company.okta.com/app/abc123eb9xnIfzlaf697/sso/saml/metadata"
  entity_id                    = "https://my.vault/v1/auth/saml"
  acs_urls                     = [
    "https://my.vault.primary/v1/auth/saml/callback",
    "https://my.vault.secondary/v1/auth/saml/callback"
  ]
  default_role                 = "default"
  verbose_logging              = true
  validate_assertion_signature = true
  validate_response_signature  = false

  tune {
    default_lease_ttl = "10m"
    max_lease_ttl     = "20m"
  }
}
`, path)
}
