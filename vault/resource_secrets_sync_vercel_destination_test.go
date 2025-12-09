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

func TestVercelSecretsSyncDestination(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-vercel")

	resourceName := "vault_secrets_sync_vercel_destination.test"

	values := testutil.SkipTestEnvUnset(t,
		"VERCEL_ACCESS_TOKEN",
		"VERCEL_PROJECT_ID",
	)
	accessToken := values[0]
	projectID := values[1]
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion116)
		}, PreventPostDestroyRefresh: true,
		Steps: []resource.TestStep{
			{
				Config: testVercelSecretsSyncDestinationConfig_initial(accessToken, projectID, destName, defaultSecretsSyncTemplate),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, fieldAccessToken, accessToken),
					resource.TestCheckResourceAttr(resourceName, fieldProjectID, projectID),
					resource.TestCheckResourceAttr(resourceName, "deployment_environments.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "deployment_environments.0", "development"),
					resource.TestCheckResourceAttr(resourceName, "deployment_environments.1", "preview"),
					resource.TestCheckResourceAttr(resourceName, "deployment_environments.2", "production"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretNameTemplate, defaultSecretsSyncTemplate),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGranularity, "secret-path"),
				),
			},
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return !meta.IsAPISupported(provider.VaultVersion119), nil
				},
				Config: testVercelSecretsSyncDestinationConfig_initial(accessToken, projectID, destName, defaultSecretsSyncTemplate),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "allowed_ipv4_addresses.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "allowed_ipv4_addresses.0", "192.168.1.1/32"),
					resource.TestCheckResourceAttr(resourceName, "allowed_ipv4_addresses.1", "10.0.0.1/32"),
					resource.TestCheckResourceAttr(resourceName, "allowed_ports.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "allowed_ports.0", "443"),
					resource.TestCheckResourceAttr(resourceName, "allowed_ports.1", "8443"),
					resource.TestCheckResourceAttr(resourceName, "disable_strict_networking", "false"),
				),
			},
			{
				Config: testVercelSecretsSyncDestinationConfig_updated(accessToken, projectID, destName, secretsKeyTemplate),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, fieldAccessToken, accessToken),
					resource.TestCheckResourceAttr(resourceName, fieldProjectID, projectID),
					resource.TestCheckResourceAttr(resourceName, "deployment_environments.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "deployment_environments.0", "development"),
					resource.TestCheckResourceAttr(resourceName, "deployment_environments.1", "preview"),
					resource.TestCheckResourceAttr(resourceName, "deployment_environments.2", "production"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretNameTemplate, secretsKeyTemplate),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGranularity, "secret-key"),
				),
			},
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return !meta.IsAPISupported(provider.VaultVersion119), nil
				},
				Config: testVercelSecretsSyncDestinationConfig_updated(accessToken, projectID, destName, secretsKeyTemplate),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "allowed_ipv6_addresses.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "allowed_ipv6_addresses.0", "2001:db8:85a3::8a2e:370:7334/128"),
					resource.TestCheckResourceAttr(resourceName, "disable_strict_networking", "true"),
				),
			},
			getVercelImportTestStep(resourceName),
		},
	})
}

func getVercelImportTestStep(resourceName string) resource.TestStep {
	ignoreFields := []string{fieldAccessToken}

	// On Vault < 1.19, the V119 networking fields won't be returned from the API
	// so we need to ignore them during import verification
	meta := testProvider.Meta().(*provider.ProviderMeta)
	if !meta.IsAPISupported(provider.VaultVersion119) {
		ignoreFields = append(ignoreFields,
			consts.FieldAllowedIPv4Addresses,
			consts.FieldAllowedIPv6Addresses,
			consts.FieldAllowedPorts,
			consts.FieldDisableStrictNetworking,
		)
	}

	return testutil.GetImportTestStep(resourceName, false, nil, ignoreFields...)
}

func testVercelSecretsSyncDestinationConfig_initial(accessToken, projectID, destName, templ string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_vercel_destination" "test" {
  name                    = "%s"
  access_token            = "%s"
  project_id              = "%s"
  deployment_environments = ["development", "preview", "production"]
  allowed_ipv4_addresses  = ["192.168.1.1/32", "10.0.0.1/32"]
  allowed_ports           = [443, 8443]
  disable_strict_networking = false
  %s
}
`, destName, accessToken, projectID, testSecretsSyncDestinationCommonConfig(templ, true, false, false))

	return ret
}

func testVercelSecretsSyncDestinationConfig_updated(accessToken, projectID, destName, templ string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_vercel_destination" "test" {
  name                    = "%s"
  access_token            = "%s"
  project_id              = "%s"
  deployment_environments = ["development", "preview", "production"]
  allowed_ipv6_addresses  = ["2001:db8:85a3::8a2e:370:7334/128"]
  disable_strict_networking = true
  %s
}
`, destName, accessToken, projectID, testSecretsSyncDestinationCommonConfig(templ, true, false, true))

	return ret
}
