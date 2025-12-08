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

const secretsKeyTemplate = "VAULT_{{ .MountAccessor | uppercase }}_{{ .SecretKey | uppercase }}"

func TestGithubSecretsSyncDestination(t *testing.T) {
	destName := acctest.RandomWithPrefix("tf-sync-dest-gh")

	resourceName := "vault_secrets_sync_gh_destination.test"

	values := testutil.SkipTestEnvUnset(t,
		"GITHUB_ACCESS_TOKEN",
		"GITHUB_REPO_OWNER",
		"GITHUB_REPO_NAME",
	)

	accessToken := values[0]
	repoOwner := values[1]
	repoName := values[2]

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion116)
		}, PreventPostDestroyRefresh: true,
		Steps: []resource.TestStep{
			{
				Config: testGithubSecretsSyncDestinationConfig_initial(accessToken, repoOwner, repoName, destName, defaultSecretsSyncTemplate),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, fieldAccessToken, accessToken),
					resource.TestCheckResourceAttr(resourceName, fieldRepositoryOwner, repoOwner),
					resource.TestCheckResourceAttr(resourceName, fieldRepositoryName, repoName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretNameTemplate, defaultSecretsSyncTemplate),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGranularity, "secret-path"),
				),
			},
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return !meta.IsAPISupported(provider.VaultVersion118), nil
				},
				Config: testGithubSecretsSyncDestinationConfig_initial(accessToken, repoOwner, repoName, destName, defaultSecretsSyncTemplate),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretsLocation, "repository"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnvironmentName, "production"),
				),
			},
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return !meta.IsAPISupported(provider.VaultVersion119), nil
				},
				Config: testGithubSecretsSyncDestinationConfig_initial(accessToken, repoOwner, repoName, destName, defaultSecretsSyncTemplate),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIPv4Addresses+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIPv4Addresses+".0", "192.168.1.0/24"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIPv4Addresses+".1", "10.0.0.0/8"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIPv6Addresses+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIPv6Addresses+".0", "2001:db8::/32"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedPorts+".#", "3"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedPorts+".0", "443"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedPorts+".1", "80"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedPorts+".2", "22"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableStrictNetworking, "false"),
				),
			},
			{
				Config: testGithubSecretsSyncDestinationConfig_updated(accessToken, repoOwner, repoName, destName, secretsKeyTemplate),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, destName),
					resource.TestCheckResourceAttr(resourceName, fieldAccessToken, accessToken),
					resource.TestCheckResourceAttr(resourceName, fieldRepositoryOwner, repoOwner),
					resource.TestCheckResourceAttr(resourceName, fieldRepositoryName, repoName),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretNameTemplate, secretsKeyTemplate),
					resource.TestCheckResourceAttr(resourceName, consts.FieldGranularity, "secret-key"),
				),
			},
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return !meta.IsAPISupported(provider.VaultVersion118), nil
				},
				Config: testGithubSecretsSyncDestinationConfig_updated(accessToken, repoOwner, repoName, destName, secretsKeyTemplate),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldSecretsLocation, "repository"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldEnvironmentName, "production"),
				),
			},
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return !meta.IsAPISupported(provider.VaultVersion119), nil
				},
				Config: testGithubSecretsSyncDestinationConfig_updated(accessToken, repoOwner, repoName, destName, secretsKeyTemplate),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIPv4Addresses+".#", "1"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIPv4Addresses+".0", "172.16.0.0/16"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIPv6Addresses+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIPv6Addresses+".0", "2001:db8::/32"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedIPv6Addresses+".1", "fe80::/10"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedPorts+".#", "2"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedPorts+".0", "443"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAllowedPorts+".1", "8080"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableStrictNetworking, "true"),
				),
			},
			getGithubImportTestStep(resourceName),
		},
	})
}

func getGithubImportTestStep(resourceName string) resource.TestStep {
	ignoreFields := []string{fieldAccessToken}

	// On Vault < 1.18, the V118 fields won't be returned from the API
	// so we need to ignore them during import verification
	meta := testProvider.Meta().(*provider.ProviderMeta)
	if !meta.IsAPISupported(provider.VaultVersion118) {
		ignoreFields = append(ignoreFields,
			consts.FieldSecretsLocation,
			consts.FieldEnvironmentName,
		)
	}

	// On Vault < 1.19, the V119 networking fields won't be returned from the API
	// so we need to ignore them during import verification
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

func testGithubSecretsSyncDestinationConfig_initial(accessToken, repoOwner, repoName, destName, templ string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_gh_destination" "test" {
  name                 = "%s"
  access_token         = "%s"
  repository_owner     = "%s"
  repository_name      = "%s"
  allowed_ipv4_addresses = ["192.168.1.0/24", "10.0.0.0/8"]
  allowed_ipv6_addresses = ["2001:db8::/32"]
  allowed_ports        = [443, 80, 22]
  disable_strict_networking = false
  secrets_location     = "repository"
  environment_name     = "production"
  %s
}
`, destName, accessToken, repoOwner, repoName, testSecretsSyncDestinationCommonConfig(templ, true, false, false))

	return ret
}

func testGithubSecretsSyncDestinationConfig_updated(accessToken, repoOwner, repoName, destName, templ string) string {
	ret := fmt.Sprintf(`
resource "vault_secrets_sync_gh_destination" "test" {
  name                 = "%s"
  access_token         = "%s"
  repository_owner     = "%s"
  repository_name      = "%s"
  allowed_ipv4_addresses = ["172.16.0.0/16"]
  allowed_ipv6_addresses = ["2001:db8::/32", "fe80::/10"]
  allowed_ports        = [443, 8080]
  disable_strict_networking = true
  secrets_location     = "repository"
  environment_name     = "production"
  %s
}
`, destName, accessToken, repoOwner, repoName, testSecretsSyncDestinationCommonConfig(templ, true, false, true))

	return ret
}
