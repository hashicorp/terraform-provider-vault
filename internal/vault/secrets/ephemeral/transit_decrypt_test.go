// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAccTransitDecrypt confirms that a transit encrypted
// secret is Correctly decrypted and read into the ephemeral resource
//
// Uses the Echo Provider to test values set in ephemeral resources
// see documentation here for more details:
// https://developer.hashicorp.com/terraform/plugin/testing/acceptance-tests/ephemeral-resources#using-echo-provider-in-acceptance-tests
func TestAccTransitDecrypt(t *testing.T) {
	testutil.SkipTestAcc(t)
	mount := acctest.RandomWithPrefix("transit")
	keyName := acctest.RandomWithPrefix("key")
	secret := "password1"

	resource.UnitTest(t, resource.TestCase{
		PreCheck: func() { testutil.TestAccPreCheck(t) },
		// Include the provider we want to test
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		// Include `echo` as a v6 provider from `terraform-plugin-testing`
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testTransitSecretConfig(mount, keyName, secret),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test_transit", tfjsonpath.New("data"), knownvalue.StringExact(secret)),
				},
			},
		},
	})
}

func testTransitSecretConfig(mount, keyName, secret string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path = "%s"
	type = "transit"
}

resource "vault_transit_secret_backend_key" "test" {
	name             = "%s"
	backend          = vault_mount.test.path
	deletion_allowed = true
}

data "vault_transit_encrypt" "encrypted" {
	backend   = vault_mount.test.path
	key       = vault_transit_secret_backend_key.test.name
	plaintext = "%s"
}

ephemeral "vault_transit_decrypt" "decrypted" {
	backend   = vault_mount.test.path
	key       = vault_transit_secret_backend_key.test.name
	ciphertext = data.vault_transit_encrypt.encrypted.ciphertext
}

provider "echo" {
	data = ephemeral.vault_transit_decrypt.decrypted.plaintext
}

resource "echo" "test_transit" {}
`, mount, keyName, secret)
}
