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

func TestAccKubernetesSecretBackend(t *testing.T) {
	testutil.SkipTestEnvSet(t, testutil.EnvVarSkipVaultNext)

	path := acctest.RandomWithPrefix("tf-test-kubernetes")
	resourceType := "vault_kubernetes_secret_backend"
	resourceName := resourceType + ".test"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeKubernetes, ""),
		Steps: []resource.TestStep{
			{
				Config: testKubernetesSecretBackend_initialConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTL, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTL, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAuditNonHMACRequestKeys+".#", "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAuditNonHMACResponseKeys+".#", "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSealWrap, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExternalEntropyAccess, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldKubernetesHost, ""),
					resource.TestCheckResourceAttr(resourceName, fieldKubernetesCACert, ""),
					resource.TestCheckResourceAttr(resourceName, fieldDisableLocalCAJWT, "false"),
				),
			},
			{
				Config: testKubernetesSecretBackend_mountTuneConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "kubernetes secrets engine"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTL, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTL, "7200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAuditNonHMACRequestKeys+".0", "test_req"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAuditNonHMACResponseKeys+".0", "test_res"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSealWrap, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExternalEntropyAccess, "true"),
					resource.TestCheckResourceAttr(resourceName, fieldKubernetesHost, ""),
					resource.TestCheckResourceAttr(resourceName, fieldKubernetesCACert, ""),
					resource.TestCheckResourceAttr(resourceName, fieldDisableLocalCAJWT, "false"),
				),
			},
			{
				Config: testKubernetesSecretBackend_updateConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "kubernetes secrets description updated"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTL, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTL, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAuditNonHMACRequestKeys+".#", "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAuditNonHMACResponseKeys+".#", "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSealWrap, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExternalEntropyAccess, "false"),
					resource.TestCheckResourceAttr(resourceName, fieldKubernetesHost, "https://127.0.0.1:63247"),
					resource.TestCheckResourceAttr(resourceName, fieldKubernetesCACert, "test_ca_cert"),
					resource.TestCheckResourceAttr(resourceName, fieldDisableLocalCAJWT, "true"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{fieldServiceAccountJWT},
			},
		},
	})
}

func testKubernetesSecretBackend_initialConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_kubernetes_secret_backend" "test" {
  path = "%s"
}`, path)
}

func testKubernetesSecretBackend_mountTuneConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_kubernetes_secret_backend" "test" {
  path                         = "%s"
  description                  = "kubernetes secrets engine"
  default_lease_ttl_seconds    = "3600"
  max_lease_ttl_seconds        = "7200"
  audit_non_hmac_request_keys  = ["test_req"]
  audit_non_hmac_response_keys = ["test_res"]
  local                        = true
  seal_wrap                    = true
  external_entropy_access      = true
}`, path)
}

func testKubernetesSecretBackend_updateConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_kubernetes_secret_backend" "test" {
  path                 = "%s"
  description          = "kubernetes secrets description updated"
  kubernetes_host      = "https://127.0.0.1:63247"
  kubernetes_ca_cert   = "test_ca_cert"
  service_account_jwt  = "header.payload.signature"
  disable_local_ca_jwt = true
}`, path)
}
