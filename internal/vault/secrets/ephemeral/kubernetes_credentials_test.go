// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ephemeralsecrets_test

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAccKubernetesServiceAccountTokenEphemeralResource_basic tests generation of
// Kubernetes service account tokens via the ephemeral resource.
// Required environment variables:
//   - K8S_HOST: Kubernetes API server URL (e.g., https://127.0.0.1:64144)
//   - K8S_CA_CERT: Kubernetes CA certificate in PEM format
//   - VAULT_SA_JWT: Service account JWT token for Vault auth
func TestAccKubernetesServiceAccountTokenEphemeralResource_basic(t *testing.T) {
	k8sHost := os.Getenv("K8S_HOST")
	k8sCACert := os.Getenv("K8S_CA_CERT")
	vaultSAJwt := os.Getenv("VAULT_SA_JWT")

	if k8sHost == "" || k8sCACert == "" || vaultSAJwt == "" {
		t.Skip("Requires K8S_HOST, K8S_CA_CERT, and VAULT_SA_JWT environment variables. Set up a Kubernetes cluster first.")
	}

	backend := "kubernetes"
	role := "test-role"

	// regex to ensure token fields are set to some value
	expectedTokenRegex, err := regexp.Compile(`^\S+$`)
	if err != nil {
		t.Fatal(err)
	}

	resource.UnitTest(t, resource.TestCase{
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
		},
		// Include the provider we want to test
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		// Include `echo` as a v6 provider from `terraform-plugin-testing`
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []resource.TestStep{
			{
				Config: testKubernetesServiceAccountTokenEphemeralResource_basic(backend, role, k8sHost, k8sCACert, vaultSAJwt),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test_k8s_token", tfjsonpath.New("data").AtMapKey(consts.FieldServiceAccountToken), knownvalue.StringRegexp(expectedTokenRegex)),
					statecheck.ExpectKnownValue("echo.test_k8s_token", tfjsonpath.New("data").AtMapKey(consts.FieldServiceAccountName), knownvalue.StringRegexp(expectedTokenRegex)),
					statecheck.ExpectKnownValue("echo.test_k8s_token", tfjsonpath.New("data").AtMapKey(consts.FieldServiceAccountNamespace), knownvalue.StringRegexp(expectedTokenRegex)),
				},
			},
		},
	})
}

func testKubernetesServiceAccountTokenEphemeralResource_basic(backend, role, k8sHost, k8sCACert, vaultSAJwt string) string {
	return fmt.Sprintf(`
resource "vault_kubernetes_secret_backend" "test" {
  path                 = "%s"
  description          = "kubernetes secrets engine"
  kubernetes_host      = "%s"
  kubernetes_ca_cert   = <<EOT
%s
EOT
  service_account_jwt  = "%s"
  disable_local_ca_jwt = true
}

resource "vault_kubernetes_secret_backend_role" "test" {
  backend                       = vault_kubernetes_secret_backend.test.path
  name                          = "%s"
  allowed_kubernetes_namespaces = ["*"]
  token_max_ttl                 = 43200
  token_default_ttl             = 3600
  service_account_name          = "test-service-account-with-generated-token"
  kubernetes_role_type          = "Role"
}

ephemeral "vault_kubernetes_service_account_token" "token" {
  backend              = vault_kubernetes_secret_backend.test.path
  role                 = vault_kubernetes_secret_backend_role.test.name
  kubernetes_namespace = "default"
  mount_id             = vault_kubernetes_secret_backend.test.id
}

provider "echo" {
  data = ephemeral.vault_kubernetes_service_account_token.token
}

resource "echo" "test_k8s_token" {}
`, backend, k8sHost, k8sCACert, vaultSAJwt, role)
}
