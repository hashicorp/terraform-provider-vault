// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

type testPKICertStore struct {
	cert             string
	serialNumber     string
	expiration       int64
	expirationWindow int64
	expectRevoked    bool
	revokeWithKey    bool
}

func TestPkiSecretBackendCert_basic(t *testing.T) {
	rootPath := "pki-root-" + strconv.Itoa(acctest.RandInt())
	intermediatePath := "pki-intermediate-" + strconv.Itoa(acctest.RandInt())

	store := &testPKICertStore{}

	resourceName := "vault_pki_secret_backend_cert.test"

	notAfter := time.Now().Add(2 * time.Hour).Format(time.RFC3339)

	checks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, "backend", intermediatePath),
		resource.TestCheckResourceAttr(resourceName, "common_name", "cert.test.my.domain"),
		resource.TestCheckResourceAttr(resourceName, "ttl", "720h"),
		resource.TestCheckResourceAttr(resourceName, "uri_sans.#", "1"),
		resource.TestCheckResourceAttr(resourceName, "uri_sans.0", "spiffe://test.my.domain"),
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendCertConfig_basic(rootPath, intermediatePath, "", true, false, false),
				Check: resource.ComposeTestCheckFunc(
					append(checks,
						resource.TestCheckResourceAttr(resourceName, "revoke", "false"),
						testCapturePKICert(resourceName, store),
						testPKICertRevocation(intermediatePath, store),
					)...,
				),
			},
			{
				// revoke the cert, expect a new one is re-issued
				Config: testPkiSecretBackendCertConfig_basic(rootPath, intermediatePath, "", true, true, false),
				Check: resource.ComposeTestCheckFunc(
					append(checks,
						resource.TestCheckResourceAttr(resourceName, "revoke", "true"),
						testPKICertRevocation(intermediatePath, store),
						testCapturePKICert(resourceName, store),
					)...,
				),
			},
			{
				// remove the cert to test revocation flow (expect no revocation)
				Config: testPkiSecretBackendCertConfig_basic(rootPath, intermediatePath, "", false, false, false),
				Check: resource.ComposeTestCheckFunc(
					testPKICertRevocation(intermediatePath, store),
				),
			},
			{
				SkipFunc: func() (bool, error) {
					meta := testProvider.Meta().(*provider.ProviderMeta)
					return !meta.IsAPISupported(provider.VaultVersion113), nil
				},
				Config: testPkiSecretBackendCertConfig_basic(rootPath, intermediatePath, "", true, false, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "user_ids.0", "foo"),
					resource.TestCheckResourceAttr(resourceName, "user_ids.1", "bar"),
				),
			},
			{
				Config: testPkiSecretBackendCertConfig_basic(rootPath, intermediatePath, notAfter, true, false, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "not_after", notAfter),
					testCapturePKICert(resourceName, store),
				),
			},
			{
				// revoke the cert with key
				Config: testPkiSecretBackendCertConfig_basic(rootPath, intermediatePath, "", true, true, true),
				Check: resource.ComposeTestCheckFunc(
					append(checks,
						resource.TestCheckResourceAttr(resourceName, "revoke_with_key", "true"),
						testPKICertRevocation(intermediatePath, store),
						testCapturePKICert(resourceName, store),
					)...,
				),
			},
		},
	})
}

func testPkiSecretBackendCertConfig_basic(rootPath, intermediatePath string, notAfter string, withCert, revoke bool, revokeWithKey bool) string {
	fragments := []string{
		fmt.Sprintf(`
resource "vault_mount" "test-root" {
  path                      = "%s"
  type                      = "pki"
  description               = "test root"
  default_lease_ttl_seconds = "8640000"
  max_lease_ttl_seconds     = "8640000"
}

resource "vault_mount" "test-intermediate" {
  path                      = "%s"
  type                      = "pki"
  description               = "test intermediate"
  default_lease_ttl_seconds = "86400"
  max_lease_ttl_seconds     = "86400"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend            = vault_mount.test-root.path
  type               = "internal"
  common_name        = "my.domain"
  ttl                = "86400"
  format             = "pem"
  private_key_format = "der"
  key_type           = "rsa"
  key_bits           = 4096
  ou                 = "test"
  organization       = "test"
  country            = "test"
  locality           = "test"
  province           = "test"
}

resource "vault_pki_secret_backend_intermediate_cert_request" "test" {
  backend     = vault_mount.test-intermediate.path
  type        = vault_pki_secret_backend_root_cert.test.type
  common_name = "test.my.domain"
}

resource "vault_pki_secret_backend_root_sign_intermediate" "test" {
  backend               = vault_mount.test-root.path
  csr                   = vault_pki_secret_backend_intermediate_cert_request.test.csr
  common_name           = "test.my.domain"
  permitted_dns_domains = [".test.my.domain"]
  ou                    = "test"
  organization          = "test"
  country               = "test"
  locality              = "test"
  province              = "test"
}

resource "vault_pki_secret_backend_intermediate_set_signed" "test" {
  backend     = vault_mount.test-intermediate.path
  certificate = vault_pki_secret_backend_root_sign_intermediate.test.certificate
}

resource "vault_pki_secret_backend_role" "test" {
  backend          = vault_pki_secret_backend_intermediate_set_signed.test.backend
  name             = "test"
  allowed_domains  = ["test.my.domain"]
  allow_subdomains = true
  allowed_uri_sans = ["spiffe://test.my.domain"]
	allowed_user_ids = ["foo", "bar"]
  max_ttl          = "3600"
  key_usage        = ["DigitalSignature", "KeyAgreement", "KeyEncipherment"]
}
`, rootPath, intermediatePath),
	}

	if withCert {
		withCertBlock := `
resource "vault_pki_secret_backend_cert" "test" {
  backend               = vault_pki_secret_backend_role.test.backend
  name                  = vault_pki_secret_backend_role.test.name
  common_name           = "cert.test.my.domain"
  uri_sans              = ["spiffe://test.my.domain"]
  user_ids              = ["foo", "bar"]
  ttl                   = "720h"
  min_seconds_remaining = 60
`

		if notAfter != "" {
			withCertBlock += fmt.Sprintf(`  not_after             = "%s"
        `, notAfter)
		}

		if revokeWithKey {
			withCertBlock += `  revoke_with_key       = true
        `
		} else {
			withCertBlock += fmt.Sprintf(`  revoke                = %t
        `, revoke)
		}

		withCertBlock += "}"
		fragments = append(fragments, withCertBlock)
	}

	return strings.Join(fragments, "\n")
}

func TestPkiSecretBackendCert_renew(t *testing.T) {
	path := "pki-root-" + strconv.Itoa(acctest.RandInt())

	store := &testPKICertStore{}

	resourceName := "vault_pki_secret_backend_cert.test"
	checks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, "backend", path),
		resource.TestCheckResourceAttr(resourceName, "common_name", "cert.test.my.domain"),
		resource.TestCheckResourceAttr(resourceName, "ttl", "1h"),
		resource.TestCheckResourceAttr(resourceName, "min_seconds_remaining", "3595"),
		resource.TestCheckResourceAttr(resourceName, "revoke", "false"),
		resource.TestCheckResourceAttrSet(resourceName, "expiration"),
		resource.TestCheckResourceAttrSet(resourceName, "serial_number"),
		resource.TestCheckResourceAttrSet(resourceName, "renew_pending"),
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed("vault_mount", consts.MountTypePKI, consts.FieldPath),
		Steps: []resource.TestStep{
			{
				Config: testPkiSecretBackendCertConfig_renew(path),
				Check: resource.ComposeTestCheckFunc(
					append(checks,
						testCapturePKICert(resourceName, store),
					)...,
				),
			},
			{
				// test renewal based on cert expiry
				// NOTE: Ideally we'd also directly test that the refreshed
				// state has renew_pending set to true before creating the plan,
				// but the test harness only exposes the state after applying
				// the plan so we can't make assertions against the intermediate
				// refresh and planning steps. Therefore we're only testing
				// that renew_pending got set to true indirectly by observing
				// that it then caused the certificate to get re-issued.
				PreConfig: testWaitCertExpiry(store),
				Config:    testPkiSecretBackendCertConfig_renew(path),
				Check: resource.ComposeTestCheckFunc(
					append(checks,
						testPKICertReIssued(resourceName, store),
						testCapturePKICert(resourceName, store),
					)...,
				),
			},
			{
				// test unmounted backend
				PreConfig: func() {
					client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()

					if err := client.Sys().Unmount(path); err != nil {
						t.Fatal(err)
					}
				},
				Config: testPkiSecretBackendCertConfig_renew(path),
				Check: resource.ComposeTestCheckFunc(
					append(checks,
						testPKICertReIssued(resourceName, store),
					)...,
				),
			},
		},
	})
}

func testWaitCertExpiry(store *testPKICertStore) func() {
	return func() {
		delay := (store.expiration - store.expirationWindow) - time.Now().Unix()
		if delay > 0 {
			time.Sleep(time.Duration(delay) * time.Second)
		}
	}
}

func testPkiSecretBackendCertConfig_renew(rootPath string) string {
	return fmt.Sprintf(`
resource "vault_mount" "test-root" {
  path                      = "%s"
  type                      = "pki"
  description               = "test root"
  default_lease_ttl_seconds = "8640000"
  max_lease_ttl_seconds     = "8640000"
}

resource "vault_pki_secret_backend_root_cert" "test" {
  backend            = vault_mount.test-root.path
  type               = "internal"
  common_name        = "my.domain"
  ttl                = "86400"
  format             = "pem"
  private_key_format = "der"
  key_type           = "rsa"
  key_bits           = 4096
  ou                 = "test"
  organization       = "test"
  country            = "test"
  locality           = "test"
  province           = "test"
}

resource "vault_pki_secret_backend_role" "test" {
  backend          = vault_pki_secret_backend_root_cert.test.backend
  name             = "test"
  allowed_domains  = ["test.my.domain"]
  allow_subdomains = true
  max_ttl          = "3600"
  key_usage        = ["DigitalSignature", "KeyAgreement", "KeyEncipherment"]
}

resource "vault_pki_secret_backend_cert" "test" {
  backend               = vault_pki_secret_backend_role.test.backend
  name                  = vault_pki_secret_backend_role.test.name
  common_name           = "cert.test.my.domain"
  ttl                   = "1h"
  auto_renew            = true
  min_seconds_remaining = "3595"
}
`, rootPath)
}

func testCapturePKICert(resourceName string, store *testPKICertStore) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		cert, ok := rs.Primary.Attributes["certificate"]
		if !ok {
			return fmt.Errorf("certificate not found in state")
		}
		store.cert = cert

		sn, ok := rs.Primary.Attributes["serial_number"]
		if !ok {
			return fmt.Errorf("serial_number not found in state")
		}
		store.serialNumber = sn

		if v, ok := rs.Primary.Attributes["expiration"]; ok {
			e, err := strconv.Atoi(v)
			if err != nil {
				return err
			}

			store.expiration = int64(e)
		}

		if v, ok := rs.Primary.Attributes["min_seconds_remaining"]; ok {
			e, err := strconv.Atoi(v)
			if err != nil {
				return err
			}

			store.expirationWindow = int64(e)
		}

		if val, ok := rs.Primary.Attributes["revoke"]; ok {
			v, err := strconv.ParseBool(val)
			if err != nil {
				return err
			}
			store.expectRevoked = v
		}

		return nil
	}
}

func testPKICertRevocation(path string, store *testPKICertStore) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		if store.cert == "" {
			return fmt.Errorf("certificate in %#v is empty", store)
		}

		addr := testProvider.Meta().(*provider.ProviderMeta).MustGetClient().Address()
		url := fmt.Sprintf("%s/v1/%s/crl", addr, path)
		c := cleanhttp.DefaultClient()
		resp, err := c.Get(url)
		if err != nil {
			return err
		}

		if resp.StatusCode > http.StatusAccepted {
			return fmt.Errorf("invalid response, %#v", resp)
		}

		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		crl, err := x509.ParseCRL(body)
		if err != nil {
			return err
		}

		p, _ := pem.Decode([]byte(store.cert))
		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			return err
		}

		for _, revoked := range crl.TBSCertList.RevokedCertificates {
			if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
				if !store.expectRevoked {
					return fmt.Errorf("cert unexpectedly revoked, serial number %v, revocations %#v",
						cert.SerialNumber, crl.TBSCertList.RevokedCertificates)
				}
				return nil
			}
		}

		if store.expectRevoked {
			return fmt.Errorf("cert not revoked, serial number %v, revocations %#v",
				cert.SerialNumber, crl.TBSCertList.RevokedCertificates)
		}

		return nil
	}
}

func testPKICert(resourceName string, check func(*x509.Certificate) error) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		certificate, ok := rs.Primary.Attributes["certificate"]
		if !ok {
			return fmt.Errorf("certificate not found in state")
		}

		p, _ := pem.Decode([]byte(certificate))
		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			return err
		}

		return check(cert)
	}
}

func testPKICertReIssued(resourceName string, store *testPKICertStore) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}
		if store.serialNumber == "" {
			return fmt.Errorf("serial_number must be set on test store %#v", store)
		}

		if store.serialNumber == rs.Primary.Attributes["serial_number"] {
			return fmt.Errorf("expected certificate not re-issued, serial_number was not changed")
		}

		return nil
	}
}
