// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccNomadSecretBackend(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-nomad")
	// TODO: test environment should exist in CI
	address, token := testutil.GetTestNomadCreds(t)

	resourceType := "vault_nomad_secret_backend"
	resourceName := resourceType + ".test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories:  testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                  func() { acctestutil.TestAccPreCheck(t) },
		PreventPostDestroyRefresh: true,
		CheckDestroy:              testCheckMountDestroyed(resourceType, consts.MountTypeNomad, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testNomadSecretBackendConfig(backend, address, token, 60, 30, 3600, 7200),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "7200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAddress, address),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "60"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "30"),
				),
			},
			{
				Config: testNomadSecretBackendConfig(backend, "foobar", token, 90, 60, 7200, 14400),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "7200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "14400"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAddress, "foobar"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "90"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "60"),
				),
			},
			{
				Config: testNomadSecretBackendConfig(backend, "foobar", token, 0, 0, -1, -1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "-1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "-1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAddress, "foobar"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "0"),
				),
			},
		},
	})
}

func TestNomadSecretBackend_remount(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-nomad")
	updatedBackend := acctest.RandomWithPrefix("tf-test-nomad-updated")

	resourceName := "vault_nomad_secret_backend.test"
	address, token := testutil.GetTestNomadCreds(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testNomadSecretBackendConfig(backend, address, token, 60, 30, 3600, 7200),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "7200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAddress, address),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "60"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "30"),
				),
			},
			{
				Config: testNomadSecretBackendConfig(updatedBackend, address, token, 60, 30, 3600, 7200),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, updatedBackend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "7200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAddress, address),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "60"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldTTL, "30"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldDescription, consts.FieldToken, consts.FieldDisableRemount, consts.FieldTokenWO, consts.FieldTokenWOVersion, consts.FieldClientKeyWO, consts.FieldClientKeyWOVersion),
		},
	})
}

func TestAccNomadSecretBackend_writeOnly(t *testing.T) {
	backend1 := acctest.RandomWithPrefix("tf-test-nomad-token")
	backend2 := acctest.RandomWithPrefix("tf-test-nomad-key")
	backend3 := acctest.RandomWithPrefix("tf-test-nomad-both")
	address, token := testutil.GetTestNomadCreds(t)
	clientKey := "-----BEGIN PRIVATE KEY-----\\ntest-key-content\\n-----END PRIVATE KEY-----"

	resourceType := "vault_nomad_secret_backend"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories:  testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                  func() { acctestutil.TestAccPreCheck(t) },
		PreventPostDestroyRefresh: true,
		CheckDestroy:              testCheckMountDestroyed(resourceType, consts.MountTypeNomad, consts.FieldBackend),
		Steps: []resource.TestStep{
			// Test 1: Create with token_wo
			{
				Config: testNomadSecretBackendConfigTokenWriteOnly(backend1, address, token, 60, 30, 3600, 7200, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceType+".test1", consts.FieldBackend, backend1),
					resource.TestCheckResourceAttr(resourceType+".test1", consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceType+".test1", consts.FieldDefaultLeaseTTLSeconds, "3600"),
					resource.TestCheckResourceAttr(resourceType+".test1", consts.FieldMaxLeaseTTLSeconds, "7200"),
					resource.TestCheckResourceAttr(resourceType+".test1", consts.FieldAddress, address),
					resource.TestCheckResourceAttr(resourceType+".test1", consts.FieldMaxTTL, "60"),
					resource.TestCheckResourceAttr(resourceType+".test1", consts.FieldTTL, "30"),
					resource.TestCheckResourceAttr(resourceType+".test1", consts.FieldTokenWOVersion, "1"),
					resource.TestCheckNoResourceAttr(resourceType+".test1", consts.FieldToken),
					resource.TestCheckNoResourceAttr(resourceType+".test1", consts.FieldTokenWO),
				),
			},
			// Test 2: Update token_wo by incrementing version
			{
				Config: testNomadSecretBackendConfigTokenWriteOnly(backend1, address, token, 90, 60, 7200, 14400, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceType+".test1", consts.FieldBackend, backend1),
					resource.TestCheckResourceAttr(resourceType+".test1", consts.FieldDescription, "test description"),
					resource.TestCheckResourceAttr(resourceType+".test1", consts.FieldDefaultLeaseTTLSeconds, "7200"),
					resource.TestCheckResourceAttr(resourceType+".test1", consts.FieldMaxLeaseTTLSeconds, "14400"),
					resource.TestCheckResourceAttr(resourceType+".test1", consts.FieldAddress, address),
					resource.TestCheckResourceAttr(resourceType+".test1", consts.FieldMaxTTL, "90"),
					resource.TestCheckResourceAttr(resourceType+".test1", consts.FieldTTL, "60"),
					resource.TestCheckResourceAttr(resourceType+".test1", consts.FieldTokenWOVersion, "2"),
					resource.TestCheckNoResourceAttr(resourceType+".test1", consts.FieldToken),
					resource.TestCheckNoResourceAttr(resourceType+".test1", consts.FieldTokenWO),
				),
			},
			// Test 3: Create with client_key_wo (using regular token field)
			{
				Config: testNomadSecretBackendConfigClientKeyWriteOnly(backend2, address, token, clientKey, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceType+".test2", consts.FieldBackend, backend2),
					resource.TestCheckResourceAttr(resourceType+".test2", consts.FieldAddress, address),
					resource.TestCheckResourceAttr(resourceType+".test2", consts.FieldClientKeyWOVersion, "1"),
					resource.TestCheckNoResourceAttr(resourceType+".test2", consts.FieldClientKey),
					resource.TestCheckNoResourceAttr(resourceType+".test2", consts.FieldClientKeyWO),
				),
			},
			// Test 4: Update client_key_wo by incrementing version
			{
				Config: testNomadSecretBackendConfigClientKeyWriteOnly(backend2, address, token, clientKey, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceType+".test2", consts.FieldBackend, backend2),
					resource.TestCheckResourceAttr(resourceType+".test2", consts.FieldAddress, address),
					resource.TestCheckResourceAttr(resourceType+".test2", consts.FieldClientKeyWOVersion, "2"),
					resource.TestCheckNoResourceAttr(resourceType+".test2", consts.FieldClientKey),
					resource.TestCheckNoResourceAttr(resourceType+".test2", consts.FieldClientKeyWO),
				),
			},
			// Test 5: Both token_wo and client_key_wo together
			{
				Config: testNomadSecretBackendConfigBothWriteOnly(backend3, address, token, clientKey, 1, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceType+".test3", consts.FieldBackend, backend3),
					resource.TestCheckResourceAttr(resourceType+".test3", consts.FieldAddress, address),
					resource.TestCheckResourceAttr(resourceType+".test3", consts.FieldTokenWOVersion, "1"),
					resource.TestCheckResourceAttr(resourceType+".test3", consts.FieldClientKeyWOVersion, "1"),
					resource.TestCheckNoResourceAttr(resourceType+".test3", consts.FieldToken),
					resource.TestCheckNoResourceAttr(resourceType+".test3", consts.FieldTokenWO),
					resource.TestCheckNoResourceAttr(resourceType+".test3", consts.FieldClientKey),
					resource.TestCheckNoResourceAttr(resourceType+".test3", consts.FieldClientKeyWO),
				),
			},
		},
	})
}

func TestAccNomadSecretBackend_writeOnlyConflicts(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-nomad")
	address, token := testutil.GetTestNomadCreds(t)
	clientKey := "-----BEGIN PRIVATE KEY-----\\ntest-key-content\\n-----END PRIVATE KEY-----"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			// Negative Test 1: token and token_wo cannot be used together
			{
				Config:      testNomadSecretBackendConfigTokenConflict(backend, address, token, 1),
				ExpectError: regexp.MustCompile(`.*conflicts with.*`),
			},
			// Negative Test 2: client_key and client_key_wo cannot be used together
			{
				Config:      testNomadSecretBackendConfigClientKeyConflict(backend, address, token, clientKey, 1),
				ExpectError: regexp.MustCompile(`.*conflicts with.*`),
			},
			// Negative Test 3: token_wo_version requires token_wo
			{
				Config:      testNomadSecretBackendConfigTokenVersionWithoutToken(backend, address, token),
				ExpectError: regexp.MustCompile(`all of .+token_wo.+ must be\s+specified`),
			},
			// Negative Test 4: client_key_wo_version requires client_key_wo
			{
				Config:      testNomadSecretBackendConfigClientKeyVersionWithoutKey(backend, address, token),
				ExpectError: regexp.MustCompile(`all of .+client_key_wo.+ must be\s+specified`),
			},
		},
	})
}

func testNomadSecretBackendConfig(backend, address, token string, maxTTL, ttl, defaultLease, maxLease int) string {
	return fmt.Sprintf(`
resource "vault_nomad_secret_backend" "test" {
	backend = "%s"
	description = "test description"
	address = "%s"
	token = "%s"
	max_ttl = "%d"
	ttl = "%d"
	default_lease_ttl_seconds = "%d"
	max_lease_ttl_seconds = "%d"
}
`, backend, address, token, maxTTL, ttl, defaultLease, maxLease)
}

func testNomadSecretBackendConfigTokenWriteOnly(backend, address, token string, maxTTL, ttl, defaultLease, maxLease, tokenVersion int) string {
	return fmt.Sprintf(`
resource "vault_nomad_secret_backend" "test1" {
	backend = "%s"
	description = "test description"
	address = "%s"
	token_wo = "%s"
	token_wo_version = %d
	max_ttl = "%d"
	ttl = "%d"
	default_lease_ttl_seconds = "%d"
	max_lease_ttl_seconds = "%d"
}
`, backend, address, token, tokenVersion, maxTTL, ttl, defaultLease, maxLease)
}

func testNomadSecretBackendConfigClientKeyWriteOnly(backend, address, token, clientKey string, clientKeyVersion int) string {
	return fmt.Sprintf(`
resource "vault_nomad_secret_backend" "test2" {
	backend = "%s"
	description = "test description"
	address = "%s"
	token = "%s"
	client_key_wo = "%s"
	client_key_wo_version = %d
}
`, backend, address, token, clientKey, clientKeyVersion)
}

func testNomadSecretBackendConfigBothWriteOnly(backend, address, token, clientKey string, tokenVersion, clientKeyVersion int) string {
	return fmt.Sprintf(`
resource "vault_nomad_secret_backend" "test3" {
	backend = "%s"
	description = "test description"
	address = "%s"
	token_wo = "%s"
	token_wo_version = %d
	client_key_wo = "%s"
	client_key_wo_version = %d
}
`, backend, address, token, tokenVersion, clientKey, clientKeyVersion)
}

func testNomadSecretBackendConfigTokenConflict(backend, address, token string, tokenVersion int) string {
	return fmt.Sprintf(`
resource "vault_nomad_secret_backend" "test" {
	backend = "%s"
	address = "%s"
	token = "%s"
	token_wo = "%s"
	token_wo_version = %d
}
`, backend, address, token, token, tokenVersion)
}

func testNomadSecretBackendConfigClientKeyConflict(backend, address, token, clientKey string, clientKeyVersion int) string {
	return fmt.Sprintf(`
resource "vault_nomad_secret_backend" "test" {
	backend = "%s"
	address = "%s"
	token = "%s"
	client_key = "%s"
	client_key_wo = "%s"
	client_key_wo_version = %d
}
`, backend, address, token, clientKey, clientKey, clientKeyVersion)
}

func testNomadSecretBackendConfigTokenVersionWithoutToken(backend, address, token string) string {
	return fmt.Sprintf(`
resource "vault_nomad_secret_backend" "test" {
	backend = "%s"
	address = "%s"
	token = "%s"
	token_wo_version = 1
}
`, backend, address, token)
}

func testNomadSecretBackendConfigClientKeyVersionWithoutKey(backend, address, token string) string {
	return fmt.Sprintf(`
resource "vault_nomad_secret_backend" "test" {
	backend = "%s"
	address = "%s"
	token = "%s"
	client_key_wo_version = 1
}
`, backend, address, token)
}
