// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package pki_test

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	pki "github.com/hashicorp/terraform-provider-vault/internal/vault/secrets/pki"
)

var (
	reBase64  = regexp.MustCompile(`^[A-Za-z0-9+/].*={0,2}$`)
	reHMAC    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reRFC3339 = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`)
)

func TestPKICAKeyExportEphemeralResourceSchema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemaRequest := ephemeral.SchemaRequest{}
	schemaResponse := &ephemeral.SchemaResponse{}

	pki.NewPKICAKeyExportEphemeralResource().Schema(ctx, schemaRequest, schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("Schema method diagnostics: %+v", schemaResponse.Diagnostics)
	}

	diagnostics := schemaResponse.Schema.ValidateImplementation(ctx)
	if diagnostics.HasError() {
		t.Fatalf("Schema validation diagnostics: %+v", diagnostics)
	}
}

// TestAccPKICAKeyExportEphemeralResource verifies the ephemeral export endpoint via the echo provider.
func TestAccPKICAKeyExportEphemeralResource(t *testing.T) {
	srcMount := acctest.RandomWithPrefix("pki-src")
	dstMount := acctest.RandomWithPrefix("pki-dst")
	resourceAddress := "echo.ca_export"

	resource.UnitTest(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestEntPreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion220)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		// Include echo provider to capture ephemeral values for state check assertions.
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testAccPKICAKeyExportConfig(srcMount, dstMount),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceAddress,
						tfjsonpath.New("data").AtMapKey("wrapped_key"),
						knownvalue.StringRegexp(reBase64)),
					statecheck.ExpectKnownValue(resourceAddress,
						tfjsonpath.New("data").AtMapKey("export_key_hmac"),
						knownvalue.StringRegexp(reHMAC)),
					statecheck.ExpectKnownValue(resourceAddress,
						tfjsonpath.New("data").AtMapKey("exported_at"),
						knownvalue.StringRegexp(reRFC3339)),
				},
			},
		},
	})
}

func testAccPKICAKeyExportConfig(srcMount, dstMount string) string {
	return fmt.Sprintf(`
resource "vault_mount" "src" {
  path = %q
  type = "pki"
}

resource "vault_pki_secret_backend_root_cert" "src_ca" {
  backend     = vault_mount.src.path
  type        = "internal"
  common_name = "BYOK Test Root CA"
  key_type    = "rsa"
  key_bits    = 2048
}

resource "vault_mount" "dst" {
  path = %q
  type = "pki"
}

resource "vault_pki_secret_backend_export_key" "wrapping_key" {
  mount    = vault_mount.dst.path
  key_type = "rsa-2048"
}

ephemeral "vault_pki_secret_backend_ca_key_export" "test" {
  mount        = vault_mount.src.path
  ca_key_uuid  = vault_pki_secret_backend_root_cert.src_ca.key_id
  public_key   = vault_pki_secret_backend_export_key.wrapping_key.public_key
  mount_id     = vault_mount.src.id
}

provider "echo" {
  data = ephemeral.vault_pki_secret_backend_ca_key_export.test
}

resource "echo" "ca_export" {}
`, srcMount, dstMount)
}
