// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKubernetesAuthBackendConfigDataSource_basic(t *testing.T) {
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("kubernetes")
	jwt := kubernetesJWT

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		CheckDestroy:             testAccCheckKubernetesAuthBackendConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKubernetesAuthBackendConfigConfig_basic(backend, jwt, kubernetesCAcert),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						consts.FieldKubernetesHost, "http://example.com:443"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						consts.FieldKubernetesCACert, kubernetesCAcert),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						"token_reviewer_jwt", jwt),
				),
			},
			{
				Config: testAccKubernetesAuthBackendConfigDataSourceConfig_basic(backend, jwt),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_config.config",
						"backend", backend),
					resource.TestCheckNoResourceAttr("data.vault_kubernetes_auth_backend_config.config",
						"token_reviewer_jwt"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_config.config",
						consts.FieldKubernetesHost, "http://example.com:443"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_config.config",
						consts.FieldKubernetesCACert, kubernetesCAcert),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_config.config",
						"pem_keys.#", "0"),
				),
			},
		},
	})
}

func TestAccKubernetesAuthBackendConfigDataSource_full(t *testing.T) {
	var p *schema.Provider
	backend := acctest.RandomWithPrefix("kubernetes")
	jwt := kubernetesJWT
	issuer := "kubernetes/serviceaccount"
	disableIssValidation := true
	disableLocalCaJwt := true
	useAnnotationsAsAliasMetadata := true

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		CheckDestroy:             testAccCheckKubernetesAuthBackendConfigDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccKubernetesAuthBackendConfigConfig_full(backend, kubernetesCAcert, jwt, issuer,
					disableIssValidation, disableLocalCaJwt, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						"backend", backend),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						consts.FieldKubernetesHost, "http://example.com:443"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						consts.FieldKubernetesCACert, kubernetesCAcert),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						"token_reviewer_jwt", jwt),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						"pem_keys.#", "1"),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						"pem_keys.0", kubernetesPEMfile),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						consts.FieldIssuer, issuer),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						consts.FieldDisableISSValidation, strconv.FormatBool(disableIssValidation)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						consts.FieldDisableLocalCAJWT, strconv.FormatBool(disableLocalCaJwt)),
				),
			},
			{
				Config: testAccKubernetesAuthBackendConfigDataSourceConfig_full(backend, jwt, issuer, disableIssValidation, disableLocalCaJwt),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_config.config",
						"backend", backend),
					resource.TestCheckNoResourceAttr("data.vault_kubernetes_auth_backend_config.config",
						"token_reviewer_jwt"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_config.config",
						consts.FieldKubernetesHost, "http://example.com:443"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_config.config",
						consts.FieldKubernetesCACert, kubernetesCAcert),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_config.config",
						"pem_keys.#", "1"),
					resource.TestCheckResourceAttr("data.vault_kubernetes_auth_backend_config.config",
						"pem_keys.0", kubernetesPEMfile),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						consts.FieldIssuer, issuer),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						consts.FieldDisableISSValidation, strconv.FormatBool(disableIssValidation)),
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						consts.FieldDisableLocalCAJWT, strconv.FormatBool(disableLocalCaJwt)),
				),
			},
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return !meta.IsAPISupported(provider.VaultVersion116), nil
				},
				Config: testAccKubernetesAuthBackendConfig_useAnnotations(backend, jwt),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_kubernetes_auth_backend_config.config",
						fieldUseAnnotationsAsAliasMetadata, strconv.FormatBool(useAnnotationsAsAliasMetadata)),
				),
			},
		},
	})
}

func testAccKubernetesAuthBackendConfigDataSourceConfig_basic(backend, jwt string) string {
	return fmt.Sprintf(`
%s

data "vault_kubernetes_auth_backend_config" "config" {
  backend = %q
}`, testAccKubernetesAuthBackendConfigConfig_basic(backend, jwt, kubernetesCAcert), backend)
}

func testAccKubernetesAuthBackendConfigDataSourceConfig_full(backend, jwt string, issuer string, disableIssValidation bool, disableLocalCaJwt bool) string {
	return fmt.Sprintf(`
%s

data "vault_kubernetes_auth_backend_config" "config" {
  backend = "%s"
}`, testAccKubernetesAuthBackendConfigConfig_full(backend, kubernetesCAcert, jwt, issuer,
		disableIssValidation, disableLocalCaJwt, false), backend)
}
