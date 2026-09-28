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

func TestDataSourceTransitEncrypt(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceTransitEncrypt_config,
				Check:  testDataSourceTransitEncrypt_check,
			},
		},
	})
}

// TestDataSourceTransitEncryptRSA_OAEP verifies that hash_algorithm and
// oaep are accepted and produce ciphertext when using an RSA key.
func TestDataSourceTransitEncryptRSA_OAEP(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceTransitEncryptRSA_oaep_config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_transit_encrypt.rsa", "hash_algorithm", "sha2-384"),
					resource.TestCheckResourceAttr("data.vault_transit_encrypt.rsa", "padding_scheme", "oaep"),
					resource.TestCheckResourceAttrSet("data.vault_transit_encrypt.rsa", "ciphertext"),
				),
			},
		},
	})
}

// TestDataSourceTransitEncryptRSA_PKCS1v15 verifies that padding_scheme=pkcs1v15
// is accepted and produces ciphertext when using an RSA key.
func TestDataSourceTransitEncryptRSA_PKCS1v15(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceTransitEncryptRSA_pkcs1v15_config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_transit_encrypt.rsa", "padding_scheme", "pkcs1v15"),
					resource.TestCheckResourceAttrSet("data.vault_transit_encrypt.rsa", "ciphertext"),
				),
			},
		},
	})
}

var testDataSourceTransitEncrypt_config = `
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

var testDataSourceTransitEncryptRSA_oaep_config = `
resource "vault_mount" "transit_rsa" {
  path        = "transit-rsa-enc-oaep"
  type        = "transit"
  description = "Transit mount for RSA OAEP encrypt tests"
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
`

var testDataSourceTransitEncryptRSA_pkcs1v15_config = `
resource "vault_mount" "transit_rsa" {
  path        = "transit-rsa-enc-pkcs1v15"
  type        = "transit"
  description = "Transit mount for RSA PKCS1v15 encrypt tests"
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
`

func testDataSourceTransitEncrypt_check(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["data.vault_transit_decrypt.test"]
	if resourceState == nil {
		return fmt.Errorf("resource not found in state %v", s.Modules[0].Resources)
	}

	iState := resourceState.Primary
	if iState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	if got, want := iState.Attributes["plaintext"], "foo"; got != want {
		return fmt.Errorf("Encrypted ciphertext %s; did not decrypt to plaintext %s", iState.Attributes["ciphertext"], iState.Attributes["plaintext"])
	}

	return nil
}
