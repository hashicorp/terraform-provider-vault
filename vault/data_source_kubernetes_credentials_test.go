// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKubernetesSecretCredentialsDataSource(t *testing.T) {
	t.Skip("Requires a Kubernetes cluster and manual setup. Should be automated.")

	dataSourceName := "data.vault_kubernetes_service_account_token.token"
	backend := acctest.RandomWithPrefix("tf-test-kubernetes")
	name := acctest.RandomWithPrefix("tf-test-role")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
		},
		Steps: []resource.TestStep{
			{
				Config: testDataSourceKubernetesServiceAccountTokenConfig(backend, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldRole, name),
					resource.TestCheckResourceAttrSet(dataSourceName, consts.FieldLeaseID),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldLeaseRenewable, "false"),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldLeaseDuration, "3600"),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldClusterRoleBinding, "false"),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldKubernetesNamespace, "test"),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldServiceAccountName, "test-service-account-with-generated-token"),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldServiceAccountNamespace, "test"),
					resource.TestCheckResourceAttrSet(dataSourceName, consts.FieldServiceAccountToken),
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
