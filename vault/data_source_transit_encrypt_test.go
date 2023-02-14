// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourceTransitEncrypt(t *testing.T) {
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceTransitEncrypt_config,
				Check:  testDataSourceTransitEncrypt_check,
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
