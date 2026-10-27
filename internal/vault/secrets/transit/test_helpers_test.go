// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package transit_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
)

// generateTestECDSAPublicKeyPEM generates a test ECDSA P-256 public key in PEM format.
func generateTestECDSAPublicKeyPEM(t *testing.T) string {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}

	return string(pem.EncodeToMemory(pemBlock))
}

// generateTestECDSAKeyPair generates a test ECDSA P-256 key pair. It returns the public
// key in PEM format and the private key as PKCS#8 DER, which is the key material format
// Vault expects inside the wrapped ciphertext for asymmetric keys.
func generateTestECDSAKeyPair(t *testing.T) (string, []byte) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})), privDER
}

// generateTestECDSAP384PublicKeyPEM generates a test ECDSA P-384 public key in PEM format.
func generateTestECDSAP384PublicKeyPEM(t *testing.T) string {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
}

// generateTestRSAPublicKeyPEM generates a test RSA 2048 public key in PEM format.
func generateTestRSAPublicKeyPEM(t *testing.T) string {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}

	return string(pem.EncodeToMemory(pemBlock))
}

func testConfigTransitMount(mount string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "transit"
}
`, mount)
}
