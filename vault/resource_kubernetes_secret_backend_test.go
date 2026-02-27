// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKubernetesSecretBackend(t *testing.T) {
	testutil.SkipTestEnvSet(t, testutil.EnvVarSkipVaultNext)

	path := acctest.RandomWithPrefix("tf-test-kubernetes")
	resourceType := "vault_kubernetes_secret_backend"
	resourceName := resourceType + ".test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeKubernetes, ""),
		Steps: []resource.TestStep{
			{
				Config: testKubernetesSecretBackend_initialConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAuditNonHMACRequestKeys+".#", "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAuditNonHMACResponseKeys+".#", "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSealWrap, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExternalEntropyAccess, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKubernetesHost, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKubernetesCACert, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableLocalCAJWT, "false"),
				),
			},
			{
				Config: testKubernetesSecretBackend_mountTuneConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "kubernetes secrets engine"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "7200"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAuditNonHMACRequestKeys+".0", "test_req"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAuditNonHMACResponseKeys+".0", "test_res"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSealWrap, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExternalEntropyAccess, "true"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKubernetesHost, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKubernetesCACert, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableLocalCAJWT, "false"),
				),
			},
			{
				Config: testKubernetesSecretBackend_updateConfig(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "kubernetes secrets description updated"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAuditNonHMACRequestKeys+".#", "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAuditNonHMACResponseKeys+".#", "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSealWrap, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExternalEntropyAccess, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKubernetesHost, "https://127.0.0.1:63247"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKubernetesCACert, "test_ca_cert"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableLocalCAJWT, "true"),
				),
			},
			{
				Config: testKubernetesSecretBackend_updateConfigV2(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDescription, "kubernetes secrets description updated"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDefaultLeaseTTLSeconds, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxLeaseTTLSeconds, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLocal, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAuditNonHMACRequestKeys+".#", "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldAuditNonHMACResponseKeys+".#", "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldSealWrap, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExternalEntropyAccess, "false"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKubernetesHost, "https://127.0.0.1:63247"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldKubernetesCACert, "test_ca_cert"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableLocalCAJWT, "true"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldServiceAccountJWT, consts.FieldServiceAccountJWTWO, consts.FieldServiceAccountJWTWOVersion},
			},
		},
	})
}

func TestAccKubernetesSecretBackend_serviceAccountJwtConflict(t *testing.T) {
	t.Parallel()

	path := acctest.RandomWithPrefix("tf-test-k8s-jwt-conflict")
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config:      testKubernetesSecretBackend_serviceAccountJwtConflict(path),
				ExpectError: regexp.MustCompile("Conflicting configuration arguments"),
				Destroy:     false,
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
	service_account_jwt_wo         = "header.payload.signature"
	service_account_jwt_wo_version = 1
  disable_local_ca_jwt = true
}`, path)
}

func testKubernetesSecretBackend_updateConfigV2(path string) string {
	return fmt.Sprintf(`
resource "vault_kubernetes_secret_backend" "test" {
  path                 = "%s"
  description          = "kubernetes secrets description updated"
  kubernetes_host      = "https://127.0.0.1:63247"
  kubernetes_ca_cert   = "test_ca_cert"
	service_account_jwt_wo         = "header.payload.signature-updated"
	service_account_jwt_wo_version = 2
  disable_local_ca_jwt = true
}`, path)
}

func testKubernetesSecretBackend_serviceAccountJwtConflict(path string) string {
	return fmt.Sprintf(`
resource "vault_kubernetes_secret_backend" "test" {
  path                           = "%s"
  description                    = "test with conflicting service account jwt"
  kubernetes_host                = "https://127.0.0.1:63247"
  kubernetes_ca_cert             = "test_ca_cert"
  service_account_jwt            = "header.payload.signature"
  service_account_jwt_wo         = "header.payload.signature-wo"
  service_account_jwt_wo_version = 1
  disable_local_ca_jwt           = true
}`, path)
}
