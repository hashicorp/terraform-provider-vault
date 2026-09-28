// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourceTransitDecrypt(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceTransitDecrypt_config,
				Check:  testDataSourceTransitDecrypt_check,
			},
		},
	})
}

// TestDataSourceTransitDecryptRSA_OAEP verifies that hash_algorith and
// oaep are accepted and round-trip correctly for RSA decrypt,
// producing the original plaintext.
func TestDataSourceTransitDecryptRSA_OAEP(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceTransitDecryptRSA_oaep_config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_transit_decrypt.rsa", "hash_algorithm", "sha2-384"),
					resource.TestCheckResourceAttr("data.vault_transit_decrypt.rsa", "padding_scheme", "oaep"),
					resource.TestCheckResourceAttr("data.vault_transit_decrypt.rsa", "plaintext", "hello rsa oaep"),
				),
			},
		},
	})
}

// TestDataSourceTransitDecryptRSA_PKCS1v15 verifies that padding_scheme=pkcs1v15
// is accepted and round-trips correctly for RSA decrypt, producing the original plaintext.
func TestDataSourceTransitDecryptRSA_PKCS1v15(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceTransitDecryptRSA_pkcs1v15_config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_transit_decrypt.rsa", "padding_scheme", "pkcs1v15"),
					resource.TestCheckResourceAttr("data.vault_transit_decrypt.rsa", "plaintext", "hello rsa pkcs1v15"),
				),
			},
		},
	})
}

var testDataSourceTransitDecrypt_config = `
resource "vault_mount" "test" {
  path        = "transit"
  type        = "transit"
  description = "This is an example mount"
}

resource "vault_transit_secret_backend_key" "test" {
  name  		   = "test"
  backend 		   = vault_mount.test.path
  deletion_allowed = true
}

data "vault_transit_encrypt" "test" {
    backend     = vault_mount.test.path
    key         = vault_transit_secret_backend_key.test.name
	plaintext   = "foo"
}

data "vault_transit_decrypt" "test" {
    backend     = vault_mount.test.path
    key         = vault_transit_secret_backend_key.test.name
	ciphertext  = data.vault_transit_encrypt.test.ciphertext
}
`

var testDataSourceTransitDecryptRSA_oaep_config = `
resource "vault_mount" "transit_rsa" {
  path        = "transit-rsa-dec-oaep"
  type        = "transit"
  description = "Transit mount for RSA OAEP encrypt/decrypt tests"
}

resource "vault_transit_secret_backend_key" "rsa" {
  name             = "rsa-oaep-test"
  backend          = vault_mount.transit_rsa.path
  type             = "rsa-2048"
  deletion_allowed = true
}

data "vault_transit_encrypt" "rsa" {
  backend        = vault_mount.transit_rsa.path
  key            = vault_transit_secret_backend_key.rsa.name
  plaintext      = "hello rsa oaep"
  hash_algorithm = "sha2-384"
  padding_scheme = "oaep"
}

data "vault_transit_decrypt" "rsa" {
  backend        = vault_mount.transit_rsa.path
  key            = vault_transit_secret_backend_key.rsa.name
  ciphertext     = data.vault_transit_encrypt.rsa.ciphertext
  hash_algorithm = "sha2-384"
  padding_scheme = "oaep"
}
`

var testDataSourceTransitDecryptRSA_pkcs1v15_config = `
resource "vault_mount" "transit_rsa" {
  path        = "transit-rsa-dec-pkcs1v15"
  type        = "transit"
  description = "Transit mount for RSA PKCS1v15 encrypt/decrypt tests"
}

resource "vault_transit_secret_backend_key" "rsa" {
  name             = "rsa-pkcs1v15-test"
  backend          = vault_mount.transit_rsa.path
  type             = "rsa-2048"
  deletion_allowed = true
}

data "vault_transit_encrypt" "rsa" {
  backend        = vault_mount.transit_rsa.path
  key            = vault_transit_secret_backend_key.rsa.name
  plaintext      = "hello rsa pkcs1v15"
  padding_scheme = "pkcs1v15"
}

data "vault_transit_decrypt" "rsa" {
  backend        = vault_mount.transit_rsa.path
  key            = vault_transit_secret_backend_key.rsa.name
  ciphertext     = data.vault_transit_encrypt.rsa.ciphertext
  padding_scheme = "pkcs1v15"
}
`

func testDataSourceTransitDecrypt_check(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["data.vault_transit_decrypt.test"]
	if resourceState == nil {
		return fmt.Errorf("resource not found in state %v", s.Modules[0].Resources)
	}

	iState := resourceState.Primary
	if iState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	if got, want := iState.Attributes["plaintext"], "foo"; got != want {
		return fmt.Errorf("Decrypted plaintext %s; did not match encrypted plaintext 'foo'", iState.Attributes["plaintext"])
	}

	return nil
}
