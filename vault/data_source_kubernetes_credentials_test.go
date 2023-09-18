// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKubernetesSecretCredentialsDataSource(t *testing.T) {
	t.Skip("Requires a Kubernetes cluster and manual setup. Should be automated.")

	dataSourceName := "data.vault_kubernetes_service_account_token.token"
	backend := acctest.RandomWithPrefix("tf-test-kubernetes")
	name := acctest.RandomWithPrefix("tf-test-role")

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
		},
		Steps: []resource.TestStep{
			{
				Config: testDataSourceKubernetesServiceAccountTokenConfig(backend, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, "backend", backend),
					resource.TestCheckResourceAttr(dataSourceName, "role", name),
					resource.TestCheckResourceAttrSet(dataSourceName, "lease_id"),
					resource.TestCheckResourceAttr(dataSourceName, "lease_renewable", "false"),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldLeaseDuration, "3600"),
					resource.TestCheckResourceAttr(dataSourceName, fieldClusterRoleBinding, "false"),
					resource.TestCheckResourceAttr(dataSourceName, fieldKubernetesNamespace, "test"),
					resource.TestCheckResourceAttr(dataSourceName, fieldServiceAccountName, "test-service-account-with-generated-token"),
					resource.TestCheckResourceAttr(dataSourceName, fieldServiceAccountNamespace, "test"),
					resource.TestCheckResourceAttrSet(dataSourceName, fieldServiceAccountToken),
				),
			},
		},
	})
}

// To run this test, Vault needs to be running in Kubernetes or the following
// vault_kubernetes_secret_backend fields need to be set:
//   - kubernetes_host
//   - kubernetes_ca_cert
//   - service_account_jwt
func testDataSourceKubernetesServiceAccountTokenConfig(backend, name string) string {
	return fmt.Sprintf(`
resource "vault_kubernetes_secret_backend" "backend" {
  path                = "%s"
}

resource "vault_kubernetes_secret_backend_role" "test" {
  backend                       = vault_kubernetes_secret_backend.backend.path
  name                          = "%s"
  allowed_kubernetes_namespaces = ["*"]
  service_account_name          = "test-service-account-with-generated-token"
}

data "vault_kubernetes_service_account_token" "token" {
  backend              = vault_kubernetes_secret_backend.backend.path
  role                 = vault_kubernetes_secret_backend_role.test.name
  kubernetes_namespace = "test"
  ttl                  = "1h"
}
`, backend, name)
}
