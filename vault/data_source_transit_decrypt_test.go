// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourceTransitDecrypt(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(testDataSourceTransitDecrypt_config, "", ""),
				Check:  testDataSourceTransitDecrypt_check,
			},
			{
				Config: fmt.Sprintf(testDataSourceTransitDecrypt_config, `type = "rsa-2048"`, ""),
				Check:  testDataSourceTransitDecrypt_check,
			},
		},
	})

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion121)
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(testDataSourceTransitDecrypt_config, `type = "aes128-cbc"`, `iv = "YmxvY2stc2l6ZS12YWx1ZQ=="`),
				Check:  testDataSourceTransitDecrypt_check,
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
  %s
}

data "vault_transit_encrypt" "test" {
    backend     = vault_mount.test.path
    key         = vault_transit_secret_backend_key.test.name
	plaintext   = "foo"
    %s
}

data "vault_transit_decrypt" "test" {
    backend     = vault_mount.test.path
    key         = vault_transit_secret_backend_key.test.name
	ciphertext  = data.vault_transit_encrypt.test.ciphertext
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
