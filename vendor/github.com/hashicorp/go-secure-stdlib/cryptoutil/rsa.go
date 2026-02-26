// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cryptoutil

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/hashicorp/go-hmac-drbg/hmacdrbg"
)

// Settable for testing
var platformReader = rand.Reader

const maxReseeds = 10000 // 7500 * 10000 * 8 = 600mm bits

// GenerateRSAKeyWithHMACDRBG generates an RSA key with a deterministic random bit generator, seeded
// with entropy from the provided random source.  Some random bit sources are quite slow, for example
// HSMs with true RNGs can take 500ms to produce enough bits to generate a single number
// to test for primality, taking literally minutes to succeed in generating a key.  As an example, when
// testing this function, one run took 921 attempts to generate a 2048 bit RSA key, which would have taken
// over 7 minutes on the HSM of the reporting customer.
//
// Instead, this function seeds a DRBG (specifically HMAC-DRBG from NIST SP800-90a) with
// entropy from a random source, then uses the output of that DRBG to generate candidate primes.
// This is still secure as the output of a DRBG is secure if the seed is sufficiently random, and
// an attacker cannot predict which numbers are chosen for primes if they don't have access to the seed.
// Additionally, the seed in this case is quite large indeed, 512 bits, well above what could be brute
// forced.
//
// This is a sanctioned approach from FIPS 186-5 (A.1.2)
func GenerateRSAKeyWithHMACDRBG(rand io.Reader, bits int) (*rsa.PrivateKey, error) {
	seed := make([]byte, (2*256)/8) // 2x maximum security strength (256-bits) from SP 800-57, Table 2
	defer func() {
		// This may not work due to the GC but worth a shot
		for i := 0; i < len(seed); i++ {
			seed[i] = 0
		}
	}()

	// Pretty unlikely to need even one reseed, but better to avoid an infinite loop.
	for i := 0; i < maxReseeds; i++ {
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		drbg := hmacdrbg.NewHmacDrbg(256, seed, []byte("generate-key-with-hmac-drbg"))
		reader := hmacdrbg.NewHmacDrbgReader(drbg)
		key, err := rsa.GenerateKey(reader, bits)
		if err != nil {
			if err.Error() == "MUST_RESEED" {
				// Oops, ran out of bytes (pretty unlikely but just in case)
				continue
			}
			return nil, err
		}
		return key, nil
	}
	return nil, fmt.Errorf("could not generate key after %d reseed of HMAC_DRBG", maxReseeds)
}

// GenerateRSAKey tests whether the random source is rand.Reader, and uses it directly if so (as it will
// be a platform RNG and fast).  If not, we assume it's some other slower source and use the HmacDRBG version.
func GenerateRSAKey(randomSource io.Reader, bits int) (*rsa.PrivateKey, error) {
	if randomSource == platformReader {
		return rsa.GenerateKey(randomSource, bits)
	}
	return GenerateRSAKeyWithHMACDRBG(randomSource, bits)
}
