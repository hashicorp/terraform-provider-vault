// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package transit_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"hash"
	"io"
	"strings"
	"testing"

	"github.com/tink-crypto/tink-go/v2/kwp/subtle"
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

// createTransitBYOKCiphertext creates a valid base64-encoded ciphertext for Vault Transit BYOK import
// using default SHA-256 RSA-OAEP wrapping.
func createTransitBYOKCiphertext(t *testing.T, wrappingKeyPEM string, keyMaterial []byte) string {
	return createTransitBYOKCiphertextWithHash(t, wrappingKeyPEM, keyMaterial, "SHA256")
}

// createTransitBYOKCiphertextWithHash creates a valid base64-encoded ciphertext for Vault Transit BYOK import
// using a specified hash function for RSA-OAEP wrapping.
func createTransitBYOKCiphertextWithHash(t *testing.T, wrappingKeyPEM string, keyMaterial []byte, hashFunction string) string {
	t.Helper()

	block, _ := pem.Decode([]byte(wrappingKeyPEM))
	if block == nil {
		t.Fatalf("failed to decode PEM block of wrapping key")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse wrapping public key: %v", err)
	}

	rsaPub, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("wrapping key is not an RSA public key")
	}

	// 1. Generate ephemeral 256-bit (32 bytes) AES key
	ephemeralAESKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, ephemeralAESKey); err != nil {
		t.Fatalf("failed to generate ephemeral AES key: %v", err)
	}

	// 2. Wrap target key material with ephemeral AES key using Google Tink KWP
	wrapKWP, err := subtle.NewKWP(ephemeralAESKey)
	if err != nil {
		t.Fatalf("failed to initialize Tink KWP: %v", err)
	}
	wrappedTargetKey, err := wrapKWP.Wrap(keyMaterial)
	if err != nil {
		t.Fatalf("failed to wrap key material with Tink KWP: %v", err)
	}

	// 3. Wrap ephemeral AES key using RSA-OAEP with specified hash function
	var h hash.Hash
	switch strings.ToUpper(hashFunction) {
	case "SHA1":
		h = sha1.New()
	case "SHA224":
		h = sha256.New224()
	case "SHA256", "":
		h = sha256.New()
	case "SHA384":
		h = sha512.New384()
	case "SHA512":
		h = sha512.New()
	default:
		t.Fatalf("unsupported hash function %q", hashFunction)
	}

	wrappedAESKey, err := rsa.EncryptOAEP(h, rand.Reader, rsaPub, ephemeralAESKey, []byte{})
	if err != nil {
		t.Fatalf("failed to encrypt ephemeral AES key with RSA-OAEP: %v", err)
	}
	if len(wrappedAESKey) != 512 {
		t.Fatalf("expected wrapped AES key length 512 bytes, got %d", len(wrappedAESKey))
	}

	// 4. Combine wrapped AES key (512 bytes) + KWP wrapped key material
	combined := append(wrappedAESKey, wrappedTargetKey...)

	return base64.StdEncoding.EncodeToString(combined)
}

func testConfigTransitMount(mount string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test" {
  path = %q
  type = "transit"
}
`, mount)
}
