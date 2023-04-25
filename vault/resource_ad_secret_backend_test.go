// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestADSecretBackend(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-ad")
	bindDN, bindPass, url := testutil.GetTestADCreds(t)

	resourceType := "vault_ad_secret_backend"
	resourceName := resourceType + ".test"
	resource.Test(t, resource.TestCase{
		Providers:                 testProviders,
		PreCheck:                  func() { testutil.TestAccPreCheck(t) },
		PreventPostDestroyRefresh: true,
		CheckDestroy:              testCheckMountDestroyed(resourceType, consts.MountTypeAD, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testADSecretBackend_initialConfig(backend, bindDN, bindPass, url),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "7200"),
					resource.TestCheckResourceAttr(resourceName, "binddn", bindDN),
					resource.TestCheckResourceAttr(resourceName, "bindpass", bindPass),
					resource.TestCheckResourceAttr(resourceName, "url", url),
					resource.TestCheckResourceAttr(resourceName, "insecure_tls", "true"),
					resource.TestCheckResourceAttr(resourceName, "userdn", "CN=Users,DC=corp,DC=example,DC=net"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "bindpass", "description", "disable_remount"),
			// TODO: on vault-1.11+ length should conflict with password_policy
			// We should re-enable this check when we have the adaptive version support.
			//{
			//	Config: testADSecretBackendConflictsConfig(
			//		resourceName, bindDN, bindPass, url, "length", 12),
			//	ExpectError: regexp.MustCompile(`.*"length": conflicts with password_policy.*`),

			//	PlanOnly: true,
			//},
			{
				Config: testADSecretBackendConflictsConfig(
					resourceName, bindDN, bindPass, url, "formatter", "{{foo}}"),
				ExpectError: regexp.MustCompile(`.*"formatter": conflicts with password_policy.*`),

				PlanOnly: true,
			},
			{
				Config: testADSecretBackend_updateConfig(backend, bindDN, bindPass, url),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "7200"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "14400"),
					resource.TestCheckResourceAttr(resourceName, "binddn", bindDN),
					resource.TestCheckResourceAttr(resourceName, "bindpass", bindPass),
					resource.TestCheckResourceAttr(resourceName, "url", url),
					resource.TestCheckResourceAttr(resourceName, "insecure_tls", "false"),
					resource.TestCheckResourceAttr(resourceName, "userdn", "CN=Users,DC=corp,DC=hashicorp,DC=com"),
				),
			},
		},
	})
}

func TestADSecretBackend_remount(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-ad")
	updatedBackend := acctest.RandomWithPrefix("tf-test-ad-updated")

	resourceName := "vault_ad_secret_backend.test"
	bindDN, bindPass, url := testutil.GetTestADCreds(t)

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testADSecretBackend_initialConfig(backend, bindDN, bindPass, url),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "7200"),
					resource.TestCheckResourceAttr(resourceName, "binddn", bindDN),
					resource.TestCheckResourceAttr(resourceName, "bindpass", bindPass),
					resource.TestCheckResourceAttr(resourceName, "url", url),
					resource.TestCheckResourceAttr(resourceName, "insecure_tls", "true"),
					resource.TestCheckResourceAttr(resourceName, "userdn", "CN=Users,DC=corp,DC=example,DC=net"),
				),
			},
			{
				Config: testADSecretBackend_initialConfig(updatedBackend, bindDN, bindPass, url),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", updatedBackend),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "7200"),
					resource.TestCheckResourceAttr(resourceName, "binddn", bindDN),
					resource.TestCheckResourceAttr(resourceName, "bindpass", bindPass),
					resource.TestCheckResourceAttr(resourceName, "url", url),
					resource.TestCheckResourceAttr(resourceName, "insecure_tls", "true"),
					resource.TestCheckResourceAttr(resourceName, "userdn", "CN=Users,DC=corp,DC=example,DC=net"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "bindpass", "description", "disable_remount"),
		},
	})
}

func testADSecretBackend_initialConfig(backend, bindDN, bindPass, url string) string {
	return fmt.Sprintf(`
resource "vault_ad_secret_backend" "test" {
  backend                   = "%s"
  description               = "test description"
  default_lease_ttl_seconds = "3600"
  max_lease_ttl_seconds     = "7200"
  binddn                    = "%s"
  bindpass                  = "%s"
  url                       = "%s"
  insecure_tls              = "true"
  userdn                    = "CN=Users,DC=corp,DC=example,DC=net"
}
`, backend, bindDN, bindPass, url)
}

func testADSecretBackend_updateConfig(backend, bindDN, bindPass, url string) string {
	return fmt.Sprintf(`
resource "vault_ad_secret_backend" "test" {
  backend                   = "%s"
  description               = "test description"
  default_lease_ttl_seconds = "7200"
  max_lease_ttl_seconds     = "14400"
  binddn                    = "%s"
  bindpass                  = "%s"
  url                       = "%s"
  insecure_tls              = "false"
  userdn                    = "CN=Users,DC=corp,DC=hashicorp,DC=com"
}
`, backend, bindDN, bindPass, url)
}

func testADSecretBackendConflictsConfig(backend, bindDN, bindPass, url, conflict string, conflictVal interface{}) string {
	var cVal string
	switch v := conflictVal.(type) {
	case string:
		cVal = fmt.Sprintf(`"%s"`, v)
	case int:
		cVal = fmt.Sprintf("%d", v)
	default:
		panic(fmt.Sprintf("unsupprted type %T", v))
	}

	config := fmt.Sprintf(`
resource "vault_ad_secret_backend" "test" {
  backend                   = "%s"
  description               = "test description"
  default_lease_ttl_seconds = "7200"
  max_lease_ttl_seconds     = "14400"
  binddn                    = "%s"
  bindpass                  = "%s"
  url                       = "%s"
  insecure_tls              = "false"
  userdn                    = "CN=Users,DC=corp,DC=hashicorp,DC=com"
  password_policy           = "foo"
  %s                        = %s
}
`, backend, bindDN, bindPass, url, conflict, cVal)

	return config
}
