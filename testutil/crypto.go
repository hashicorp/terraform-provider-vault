// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package testutil

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
	"hash"
	"io"
	"strings"
	"testing"

	"github.com/tink-crypto/tink-go/v2/kwp/subtle"
)

// CreateBYOKCiphertext creates a valid base64-encoded ciphertext for a Vault BYOK import
// (Transit or Transform). hashFunction is the hash used for the RSA-OAEP wrapping step
// (SHA1, SHA224, SHA256, SHA384 or SHA512) and should match the hash_function the resource is configured with.
func CreateBYOKCiphertext(t *testing.T, wrappingKeyPEM string, keyMaterial []byte, hashFunction string) string {
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
	case "SHA256":
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

// RandomAESKey generates 32 random bytes, usable as raw AES-256 key material.
func RandomAESKey(t *testing.T) []byte {
	t.Helper()

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("failed to generate random AES key: %v", err)
	}
	return key
}

// GenerateECDSAKeyPair generates an ECDSA key on the given curve. It returns the public key as a
// PKIX PEM block and the private key as PKCS#8 DER, which is the key material format Vault expects
// inside a wrapped BYOK ciphertext for asymmetric keys.
func GenerateECDSAKeyPair(t *testing.T, curve elliptic.Curve) (string, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	return publicKeyPEM(t, &key.PublicKey), privDER
}

// GenerateRSAPublicKeyPEM generates an RSA key of the given size and returns its public key as a
// PKIX PEM block.
func GenerateRSAPublicKeyPEM(t *testing.T, bits int) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	return publicKeyPEM(t, &key.PublicKey)
}

func publicKeyPEM(t *testing.T, pub any) string {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}
