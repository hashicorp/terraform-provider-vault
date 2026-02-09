// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pki_external_ca_test

import (
	"crypto/x509/pkix"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/hashicorp/vault/sdk/helper/testcluster/docker"
	"github.com/stretchr/testify/require"
)

func TestAccPKIExternalCAOrderResource_identifiers(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-pki-ext-ca")
	accountName := acctest.RandomWithPrefix("test-account")
	roleName := acctest.RandomWithPrefix("test-role")
	resourceName := "vault_pki_secret_backend_external_ca_order.test"

	ca, directoryUrl := setupVaultAndPebble(t)
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.PreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion118)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccPKIExternalCAOrderConfig_identifiers(backend, accountName, roleName, directoryUrl, ca),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, "role_name", roleName),
					resource.TestCheckResourceAttr(resourceName, "identifiers.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "identifiers.0", "example.com"),
					resource.TestCheckResourceAttr(resourceName, "identifiers.1", "test.example.com"),
					resource.TestCheckResourceAttrSet(resourceName, "order_id"),
					resource.TestCheckResourceAttrSet(resourceName, "order_status"),
					resource.TestCheckResourceAttrSet(resourceName, "creation_date"),
					resource.TestCheckResourceAttrSet(resourceName, "next_work_date"),
					resource.TestCheckResourceAttrSet(resourceName, "last_update"),
					resource.TestCheckResourceAttrSet(resourceName, "expires"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "expires", "last_update", "next_work_date", "order_status"),
		},
	})
}

func setupVaultAndPebble(t *testing.T) (string, string) {
	if os.Getenv("VAULT_ADDR") != "" {
		ca, port, _ := testutil.SetupPebbleAcmeServerWithOption(t, testutil.NewPebbleOptions())
		directoryUrl := fmt.Sprintf("https://localhost:%d/dir", port)
		return ca, directoryUrl
	}
	opts := docker.DefaultOptions(t)
	opts.ImageRepo = "hashicorp/vault-enterprise"
	opts.NumCores = 1
	opts.Envs = []string{"VAULT_LICENSE=" + os.Getenv("VAULT_LICENSE")}
	// TODO remove this once there's a vault-enterprise image that contains pki-external-ca
	opts.VaultBinary = "/Users/ncc/hc/vault-enterprise/vault.linux"
	cluster := docker.NewTestDockerCluster(t, opts)
	ca, _, address := testutil.SetupPebbleAcmeServerWithOption(t, testutil.NewPebbleOptions().SetNetworkName(
		cluster.Nodes()[0].(*docker.DockerClusterNode).ContainerNetworkName))
	directoryUrl := fmt.Sprintf("https://%s/dir", address)
	client := cluster.Nodes()[0].APIClient()
	os.Setenv(api.EnvVaultAddress, client.Address())
	os.Setenv(api.EnvVaultToken, client.Token())
	os.Setenv(api.EnvVaultCACertBytes, string(cluster.CACertPEM))

	return ca, directoryUrl
}

func TestAccPKIExternalCAOrderResource_csr(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-pki-ext-ca")
	accountName := acctest.RandomWithPrefix("test-account")
	roleName := acctest.RandomWithPrefix("test-role")
	resourceName := "vault_pki_secret_backend_external_ca_order.test"
	host := "example.com"

	// Generate a test CSR
	cb := &certutil.CreationBundle{
		Params: &certutil.CreationParameters{
			KeyBits: 2048,
			KeyType: "rsa",
			Subject: pkix.Name{
				CommonName: "www." + host,
			},
			DNSNames: []string{"www." + host, host},
		},
	}

	csr, err := certutil.CreateCSR(cb, true)
	require.NoError(t, err)

	csrb, err := csr.ToCSRBundle()
	require.NoError(t, err)

	ca, directoryUrl := setupVaultAndPebble(t)

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck: func() {
			acctestutil.PreCheck(t)
			acctestutil.SkipIfAPIVersionLT(t, provider.VaultVersion118)
		},
		Steps: []resource.TestStep{
			{
				Config: testAccPKIExternalCAOrderConfig_csr(backend, accountName, roleName, directoryUrl, ca, csrb.CSR),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMount, backend),
					resource.TestCheckResourceAttr(resourceName, "role_name", roleName),
					resource.TestCheckResourceAttrSet(resourceName, "csr"),
					resource.TestCheckResourceAttrSet(resourceName, "order_id"),
					resource.TestCheckResourceAttrSet(resourceName, "order_status"),
					resource.TestCheckResourceAttrSet(resourceName, "creation_date"),
					resource.TestCheckResourceAttrSet(resourceName, "expires"),
					// Identifiers should be populated from the CSR
					resource.TestCheckResourceAttr(resourceName, "identifiers.#", "2"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "csr", "expires", "last_update", "next_work_date", "order_status"),
		},
	})
}

func testAccPKIExternalCAOrderConfig_identifiers(backend, accountName, roleName, directoryUrl, ca string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "pki-external-ca"
  description = "PKI External CA test"
}

resource "vault_pki_secret_backend_acme_account" "test" {
  mount          = vault_mount.test.path
  name           = "%s"
  directory_url  = "%s"
  email_contacts = ["test@example.com"]
  key_type       = "ec-256"
  trusted_ca     = <<EOT
%s
EOT
}

resource "vault_pki_secret_backend_external_ca_role" "test" {
  mount                       = vault_mount.test.path
  name                        = "%s"
  acme_account_name           = vault_pki_secret_backend_acme_account.test.name
  allowed_domains             = ["example.com", "*.example.com"]
  allowed_domains_options     = ["bare_domains", "subdomains", "wildcards"]
  allowed_challenge_types     = ["http-01", "dns-01", "tls-alpn-01"]
  csr_generate_key_type       = "ec-256"
  csr_identifier_population   = "cn_first"
  force                       =  "true"
}

resource "vault_pki_secret_backend_external_ca_order" "test" {
  mount       = vault_mount.test.path
  role_name   = vault_pki_secret_backend_external_ca_role.test.name
  identifiers = ["example.com", "test.example.com"]
}
`, backend, accountName, directoryUrl, ca, roleName)
}

func testAccPKIExternalCAOrderConfig_csr(backend, accountName, roleName, directoryUrl, ca, csrPem string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "pki-external-ca"
  description = "PKI External CA test"
}

resource "vault_pki_secret_backend_acme_account" "test" {
  mount          = vault_mount.test.path
  name           = "%s"
  directory_url  = "%s"
  email_contacts = ["test@example.com"]
  key_type       = "ec-256"
  trusted_ca     = <<EOT
%s
EOT
}

resource "vault_pki_secret_backend_external_ca_role" "test" {
  mount                       = vault_mount.test.path
  name                        = "%s"
  acme_account_name           = vault_pki_secret_backend_acme_account.test.name
  allowed_domains             = ["example.com", "*.example.com"]
  allowed_domains_options     = ["bare_domains", "subdomains", "wildcards"]
  allowed_challenge_types     = ["http-01", "dns-01", "tls-alpn-01"]
  csr_generate_key_type       = "ec-256"
  csr_identifier_population   = "cn_first"
  force                       =  "true"
}

resource "vault_pki_secret_backend_external_ca_order" "test" {
  mount     = vault_mount.test.path
  role_name = vault_pki_secret_backend_external_ca_role.test.name
  csr       = <<EOT
%s
EOT
}
`, backend, accountName, directoryUrl, ca, roleName, csrPem)
}

// Made with Bob
