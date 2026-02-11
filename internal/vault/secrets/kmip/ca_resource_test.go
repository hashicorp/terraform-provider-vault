// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kmip_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKMIPCA_generate(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	path := acctest.RandomWithPrefix("tf-test-kmip")
	name := acctest.RandomWithPrefix("ca")
	resourceType := "vault_kmip_secret_ca"
	resourceName := resourceType + ".test"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKMIPCA_generateConfig(path, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "key_type", "ec"),
					resource.TestCheckResourceAttr(resourceName, "key_bits", "256"),
					resource.TestCheckResourceAttr(resourceName, "ttl", "31536000"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "ttl", "key_type", "key_bits"),
		},
	})
}

func TestAccKMIPCA_import(t *testing.T) {
	testutil.SkipTestAccEnt(t)

	path := acctest.RandomWithPrefix("tf-test-kmip")
	name := acctest.RandomWithPrefix("ca")
	resourceType := "vault_kmip_secret_ca"
	resourceName := resourceType + ".test"

	// Generate a self-signed certificate for testing
	caPem, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		PreCheck:                 func() { testutil.TestEntPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKMIPCA_importConfig(path, name, caPem),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "scope_name", "test-scope"),
					resource.TestCheckResourceAttr(resourceName, "role_name", "test-role"),
					resource.TestCheckResourceAttrSet(resourceName, "ca_pem"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "ca_pem", "ttl"),
			{
				Config: testKMIPCA_importUpdateConfig(path, name, caPem),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, path),
					resource.TestCheckResourceAttr(resourceName, consts.FieldName, name),
					resource.TestCheckResourceAttr(resourceName, "scope_name", "updated-scope"),
					resource.TestCheckResourceAttr(resourceName, "role_name", "updated-role"),
				),
			},
		},
	})
}

// generateSelfSignedCert creates a self-signed EC certificate bundle for testing
func generateSelfSignedCert() (string, error) {
	// Generate EC private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Organization"},
			CommonName:   "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return string(certPEM), nil
}

func testKMIPCA_generateConfig(path, name string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path                         = "%s"
}

resource "vault_kmip_secret_ca" "test" {
  path     = vault_kmip_secret_backend.test.path
  name     = "%s"
  key_type = "ec"
  key_bits = 256
  ttl      = 31536000
}`, path, name)
}

func testKMIPCA_importConfig(path, name, caPem string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path                         = "%s"
}

resource "vault_kmip_secret_ca" "test" {
  path       = vault_kmip_secret_backend.test.path
  name       = "%s"
  ca_pem     = <<EOT
%s
EOT
  scope_name = "test-scope"
  role_name  = "test-role"
}`, path, name, caPem)
}

func testKMIPCA_importUpdateConfig(path, name, caPem string) string {
	return fmt.Sprintf(`
resource "vault_kmip_secret_backend" "test" {
  path                         = "%s"
}

resource "vault_kmip_secret_ca" "test" {
  path       = vault_kmip_secret_backend.test.path
  name       = "%s"
  ca_pem     = <<EOT
%s
EOT
  scope_name = "updated-scope"
  role_name  = "updated-role"
}`, path, name, caPem)
}

// Made with Bob
