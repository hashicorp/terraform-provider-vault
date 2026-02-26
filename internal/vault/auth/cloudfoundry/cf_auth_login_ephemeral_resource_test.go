// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cloudfoundry_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/config"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

const cfSigningTimeFormat = "2006-01-02T15:04:05Z"

// cfLoginParams extends cfTestParams with the CF instance certificate and key
// needed to generate a valid login signature.
type cfLoginParams struct {
	cfTestParams
	instanceCert string // PEM contents of the instance certificate
	instanceKey  string // PEM contents of the PKCS#1 RSA private key
}

// cfLoginParamsFromEnv builds cfLoginParams from environment variables.
// Both files must be provided via environment variables:
//
//	CF_TEST_INSTANCE_CERT_FILE - path to the CF instance certificate (PEM)
//	CF_TEST_INSTANCE_KEY_FILE  - path to the PKCS#1 RSA private key (PEM)
//
// The test is skipped if either variable is unset or the file cannot be read.
func cfLoginParamsFromEnv(t *testing.T) cfLoginParams {
	t.Helper()

	base := cfTestParamsFromEnv(t)

	certFile := os.Getenv("CF_TEST_INSTANCE_CERT_FILE")
	if certFile == "" {
		t.Skip("CF_TEST_INSTANCE_CERT_FILE not set: skipping CF login test")
	}
	keyFile := os.Getenv("CF_TEST_INSTANCE_KEY_FILE")
	if keyFile == "" {
		t.Skip("CF_TEST_INSTANCE_KEY_FILE not set: skipping CF login test")
	}

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Skipf("skipping CF login test: cannot read instance cert %s: %v", certFile, err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		t.Skipf("skipping CF login test: cannot read instance key %s: %v", keyFile, err)
	}

	return cfLoginParams{
		cfTestParams: base,
		instanceCert: string(certPEM),
		instanceKey:  string(keyPEM),
	}
}

// generateCFSignature returns a signing_time string and a "v1:<base64>"
// RSA-PSS-SHA256 signature, replicating vault-plugin-auth-cf/signatures/version1.go:
//
//	SHA256( signing_time + cf_instance_cert + role ), then RSA-PSS with SHA256.
//
// The CF backend default LoginMaxSecNotBefore is 300 s, so credentials generated
// at test startup stay valid for the entire test run.
func generateCFSignature(t *testing.T, instanceKeyPEM, instanceCert, roleName string) (signingTime, signature string) {
	t.Helper()

	block, _ := pem.Decode([]byte(instanceKeyPEM))
	if block == nil {
		t.Fatal("failed to PEM-decode instance key")
	}
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parsing PKCS#1 private key: %v", err)
	}

	now := time.Now().UTC()
	signingTime = now.Format(cfSigningTimeFormat)

	// Matches the vault-plugin-auth-cf signing algorithm (version1.go).
	toHash := signingTime + instanceCert + roleName
	hashed := sha256.Sum256([]byte(toHash))

	sigBytes, err := rsa.SignPSS(rand.Reader, rsaKey, crypto.SHA256, hashed[:], nil)
	if err != nil {
		t.Fatalf("RSA-PSS signing: %v", err)
	}
	signature = "v1:" + base64.StdEncoding.EncodeToString(sigBytes)
	return
}

// TestAccCFAuthLogin exercises the vault_cf_auth_login ephemeral resource.
//
// Terraform opens ephemeral resources during the plan phase, so the CF auth
// backend infrastructure must already exist before the ephemeral resource is
// introduced. The test uses three steps:
//
//  1. Create the CF auth infrastructure (auth backend + config + role).
//  2. Add the ephemeral login resource - a successful apply proves Vault
//     accepts the CF credentials.
//  3. Add a Vault provider alias authenticated with the issued client_token
//     and read auth/token/lookup-self, proving the token is usable.
func TestAccCFAuthLogin(t *testing.T) {
	p := cfLoginParamsFromEnv(t)
	mount := acctest.RandomWithPrefix("cf-mount")
	roleName := "test-role"

	// Generate signing credentials once. The CF backend default
	// LoginMaxSecNotBefore window (300 s) covers the full test duration.
	signingTime, sig := generateCFSignature(t, p.instanceKey, p.instanceCert, roleName)

	loginVars := config.Variables{
		"cf_instance_cert": config.StringVariable(p.instanceCert),
		"signing_time":     config.StringVariable(signingTime),
		"signature":        config.StringVariable(sig),
	}

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Apply only the CF infrastructure. Ephemeral resources are
			// opened during Terraform plan, so the CF mount must already exist
			// before the login resource is introduced in step 2.
			{
				Config: testAccCFAuthInfraConfig(mount, roleName, p),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 2: Add the ephemeral login resource on top of the existing
			// infrastructure. A successful apply proves Vault accepted the
			// CF credentials.
			{
				Config:          testAccCFAuthLoginConfig(mount, roleName, p),
				ConfigVariables: loginVars,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 3: Forward client_token to a provider alias and call
			// auth/token/lookup-self. Non-empty data proves the token is
			// a real, working Vault credential.
			{
				Config:          testAccCFAuthLoginWithTokenUseConfig(mount, roleName, p),
				ConfigVariables: loginVars,
				Check: resource.ComposeTestCheckFunc(
					// data.% being set means the data source returned token
					// metadata - the CF token authenticated successfully.
					resource.TestCheckResourceAttrSet(
						"data.vault_generic_secret.token_self", "data.%"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 4: Destroy all CF resources (keep only the mount).
			{
				Config: testAccCFAuthBackendConfigMountOnly(mount),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectNonEmptyPlan(),
						plancheck.ExpectResourceAction("vault_cf_auth_backend_config.test", plancheck.ResourceActionDestroy),
						plancheck.ExpectResourceAction("vault_cf_auth_backend_role.test", plancheck.ResourceActionDestroy),
						plancheck.ExpectResourceAction("vault_policy.cf_test", plancheck.ResourceActionDestroy),
					},
				},
			},
		},
	})
}

// testAccCFAuthInfraConfig creates only the CF auth infrastructure without any
// ephemeral resource. Used as the prerequisite step so the CF backend mount
// already exists when the login step is planned.
func testAccCFAuthInfraConfig(mount, roleName string, p cfLoginParams) string {
	return fmt.Sprintf(`
%s

resource "vault_policy" "cf_test" {
  name   = "cf-auth-login-test"
  policy = <<EOT
path "auth/token/create" {
  capabilities = ["create", "update", "sudo"]
}
EOT
}

resource "vault_cf_auth_backend_config" "test" {
  mount                    = vault_auth_backend.cf.path
  identity_ca_certificates = ["%s"]
  cf_api_addr              = "%s"
  cf_username              = "%s"
  cf_password_wo           = "%s"
  cf_password_wo_version   = 1
  login_max_seconds_not_before = 300
}

resource "vault_cf_auth_backend_role" "test" {
  mount = vault_auth_backend.cf.path
  name  = "%s"

  disable_ip_matching = true
  token_policies      = [vault_policy.cf_test.name]

  depends_on = [vault_cf_auth_backend_config.test]
}
`,
		testAccCFAuthBackendConfigMountOnly(mount),
		escapeHCL(p.ca), p.apiAddr, p.username, p.password,
		roleName,
	)
}

// testAccCFAuthLoginConfig adds the ephemeral vault_cf_auth_login resource to
// the existing CF infrastructure. Sensitive inputs arrive via ConfigVariables
// to avoid HCL escaping issues with PEM blocks and base64 signatures.
func testAccCFAuthLoginConfig(mount, roleName string, p cfLoginParams) string {
	return fmt.Sprintf(`
variable "cf_instance_cert" { sensitive = true }
variable "signing_time"     {}
variable "signature"        { sensitive = true }

%s

resource "vault_policy" "cf_test" {
  name   = "cf-auth-login-test"
  policy = <<EOT
path "auth/token/create" {
  capabilities = ["create", "update", "sudo"]
}
EOT
}

resource "vault_cf_auth_backend_config" "test" {
  mount                    = vault_auth_backend.cf.path
  identity_ca_certificates = ["%s"]
  cf_api_addr              = "%s"
  cf_username              = "%s"
  cf_password_wo           = "%s"
  cf_password_wo_version   = 1
  login_max_seconds_not_before = 300
}

resource "vault_cf_auth_backend_role" "test" {
  mount = vault_auth_backend.cf.path
  name  = "%s"

  disable_ip_matching = true
  token_policies      = [vault_policy.cf_test.name]

  depends_on = [vault_cf_auth_backend_config.test]
}

ephemeral "vault_cf_auth_login" "test" {
  mount            = vault_auth_backend.cf.path
  role             = vault_cf_auth_backend_role.test.name
  cf_instance_cert = var.cf_instance_cert
  signing_time     = var.signing_time
  signature        = var.signature
}
`,
		testAccCFAuthBackendConfigMountOnly(mount),
		escapeHCL(p.ca), p.apiAddr, p.username, p.password,
		roleName,
	)
}

// testAccCFAuthLoginWithTokenUseConfig extends the login config with a Vault
// provider alias authenticated via the CF-issued token. A vault_generic_secret
// data source reads auth/token/lookup-self through that alias to verify the
// token can make real Vault API calls.
func testAccCFAuthLoginWithTokenUseConfig(mount, roleName string, p cfLoginParams) string {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "http://localhost:8200"
	}

	return fmt.Sprintf(`
variable "cf_instance_cert" { sensitive = true }
variable "signing_time"     {}
variable "signature"        { sensitive = true }

%s

resource "vault_policy" "cf_test" {
  name   = "cf-auth-login-test"
  policy = <<EOT
path "auth/token/create" {
  capabilities = ["create", "update", "sudo"]
}
EOT
}

resource "vault_cf_auth_backend_config" "test" {
  mount                    = vault_auth_backend.cf.path
  identity_ca_certificates = ["%s"]
  cf_api_addr              = "%s"
  cf_username              = "%s"
  cf_password_wo           = "%s"
  cf_password_wo_version   = 1
  login_max_seconds_not_before = 300
}

resource "vault_cf_auth_backend_role" "test" {
  mount = vault_auth_backend.cf.path
  name  = "%s"

  disable_ip_matching = true
  token_policies      = [vault_policy.cf_test.name]

  depends_on = [vault_cf_auth_backend_config.test]
}

ephemeral "vault_cf_auth_login" "test" {
  mount            = vault_auth_backend.cf.path
  role             = vault_cf_auth_backend_role.test.name
  cf_instance_cert = var.cf_instance_cert
  signing_time     = var.signing_time
  signature        = var.signature
}

# A second Vault provider instance authenticated with the CF-issued token.
provider "vault" {
  alias   = "cf_auth"
  address = "%s"
  token   = ephemeral.vault_cf_auth_login.test.client_token
}

# Token self-lookup via the CF-authenticated provider alias.
# Any valid Vault token may call this via the built-in default policy.
data "vault_generic_secret" "token_self" {
  provider = vault.cf_auth
  path     = "auth/token/lookup-self"
}
`,
		testAccCFAuthBackendConfigMountOnly(mount),
		escapeHCL(p.ca), p.apiAddr, p.username, p.password,
		roleName,
		vaultAddr,
	)
}
