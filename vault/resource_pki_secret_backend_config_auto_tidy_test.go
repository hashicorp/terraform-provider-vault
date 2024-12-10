// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccPKISecretBackendConfigAutoTidy_basic(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-pki")
	resourceType := "vault_pki_secret_backend_config_auto_tidy"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion111)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypePKI, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testAccPKISecretBackendConfigAutoTidy_basic(backend, ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, "enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "interval_duration", "259200"),
					resource.TestCheckResourceAttr(resourceName, "safety_buffer", "86400"),
					resource.TestCheckResourceAttr(resourceName, "publish_stored_certificate_count_metrics", "false"),
					resource.TestCheckResourceAttr(resourceName, "tidy_acme", "true"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil),
		},
	})
}

func testAccPKISecretBackendConfigAutoTidy_basic(path, extraFields string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
	path        = "%s"
	type        = "pki"
    description = "PKI secret engine mount"
}

resource "vault_pki_secret_backend_config_auto_tidy" "test" {
  backend                                  = vault_mount.test.path
  enabled                                  = true
  interval_duration                        = 259200
  safety_buffer                            = 86400
  publish_stored_certificate_count_metrics = false
  tidy_acme                                = true
  %s
}`, path, extraFields)
}
