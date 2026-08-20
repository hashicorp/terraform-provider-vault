// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestTerraformCloudSecretBackend(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-terraform-cloud")

	resourceType := "vault_terraform_cloud_secret_backend"
	resourceName := resourceType + ".test"
	token := "randomized-token-12392183123"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeTerraform, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testTerraformCloudSecretBackend_initialConfig(backend, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr(resourceName, "address", "https://app.terraform.io"),
					resource.TestCheckResourceAttr(resourceName, "token", token),
					resource.TestCheckResourceAttr(resourceName, "base_path", "/api/v2/"),
				),
			},
			{
				Config: testTerraformCloudSecretBackend_updateConfig(backend, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "0"),
					resource.TestCheckResourceAttr(resourceName, "address", "https://app.terraform.io/not"),
					resource.TestCheckResourceAttr(resourceName, "token", token),
					resource.TestCheckResourceAttr(resourceName, "base_path", "/not/api/v2/"),
				),
			},
		},
	})
}

func TestTerraformCloudSecretBackend_remount(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-terraform-cloud")
	updatedBackend := acctest.RandomWithPrefix("tf-test-terraform-cloud-updated")

	resourceType := "vault_terraform_cloud_secret_backend"
	resourceName := resourceType + ".test"
	token := "randomized-token-12392183123"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeTerraform, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testTerraformCloudSecretBackend_initialConfig(backend, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr(resourceName, "address", "https://app.terraform.io"),
					resource.TestCheckResourceAttr(resourceName, "token", token),
					resource.TestCheckResourceAttr(resourceName, "base_path", "/api/v2/"),
				),
			},
			{
				Config: testTerraformCloudSecretBackend_initialConfig(updatedBackend, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", updatedBackend),
					resource.TestCheckResourceAttr(resourceName, "description", "test description"),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl_seconds", "3600"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl_seconds", "86400"),
					resource.TestCheckResourceAttr(resourceName, "address", "https://app.terraform.io"),
					resource.TestCheckResourceAttr(resourceName, "token", token),
					resource.TestCheckResourceAttr(resourceName, "base_path", "/api/v2/"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "description", "token", "disable_remount"),
		},
	})
}

func TestTerraformCloudSecretBackend_tokenWO(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-terraform-cloud")

	resourceType := "vault_terraform_cloud_secret_backend"
	resourceName := resourceType + ".test"
	token := "randomized-token-12392183123"

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		CheckDestroy:             testCheckMountDestroyed(resourceType, consts.MountTypeTerraform, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testTerraformCloudSecretBackend_tokenWoInitialConfig(backend, token),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "address", "https://app.terraform.io"),
					resource.TestCheckResourceAttr(resourceName, "token_wo_version", "1"),
					resource.TestCheckResourceAttr(resourceName, "base_path", "/api/v2/"),
				),
			},
			{
				Config: testTerraformCloudSecretBackend_tokenWoUpdatedConfig(backend, token, 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "backend", backend),
					resource.TestCheckResourceAttr(resourceName, "token_wo_version", "2"),
				),
			},
			{
				Config:      testTerraformCloudSecretBackend_tokenWoNoVersion(backend, 3),
				ExpectError: regexp.MustCompile(`all of.*token_wo,token_wo_version.*must be specified`),
			},
			{
				Config:      testTerraformCloudSecretBackend_tokenWoEmptyString(backend, 4),
				ExpectError: regexp.MustCompile(`token_wo must be provided`),
			},
		},
	})
}

// TestTerraformCloudSecretBackend_automatedRotation tests that the automated
// root token rotation parameters are accepted and round-tripped by the
// Terraform Cloud secret backend resource. Automated rotation relies on the
// Vault Enterprise Rotation Manager.
func TestTerraformCloudSecretBackend_automatedRotation(t *testing.T) {
	backend := acctest.RandomWithPrefix("tf-test-terraform-cloud")

	resourceType := "vault_terraform_cloud_secret_backend"
	resourceName := resourceType + ".test"
	vals := testutil.SkipTestEnvUnset(t, "TEST_TF_TOKEN")
	token := vals[0]

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck: func() {
			testutil.TestEntPreCheck(t)
			SkipIfAPIVersionLT(t, testProvider.Meta(), provider.VaultVersion220)
		},
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeTerraform, consts.FieldBackend),
		Steps: []resource.TestStep{
			{
				Config: testTerraformCloudSecretBackend_automatedRotation(backend, token, "", 10, 0, 3600, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldBackend, backend),
					resource.TestCheckResourceAttr(resourceName, consts.FieldExplicitMaxTTL, "3600"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "10"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "false"),
				),
			},
			// switch to a schedule-based rotation and zero-out rotation_period
			{
				Config: testTerraformCloudSecretBackend_automatedRotation(backend, token, "*/20 * * * *", 0, 120, 3600, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "120"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, "*/20 * * * *"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "false"),
				),
			},
			// rotation_window is not compatible with rotation_period
			{
				Config:      testTerraformCloudSecretBackend_automatedRotation(backend, token, "", 30, 120, 3600, true),
				ExpectError: regexp.MustCompile("rotation_window does not apply to period"),
			},
			// zero-out rotation_schedule and rotation_window, disable rotation
			{
				Config: testTerraformCloudSecretBackend_automatedRotation(backend, token, "", 30, 0, 3600, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationPeriod, "30"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationWindow, "0"),
					resource.TestCheckResourceAttr(resourceName, consts.FieldRotationSchedule, ""),
					resource.TestCheckResourceAttr(resourceName, consts.FieldDisableAutomatedRotation, "true"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldToken, consts.FieldDisableRemount),
		},
	})
}

func testTerraformCloudSecretBackend_automatedRotation(backend, token, schedule string, period, window, explicitMaxTTL int, disable bool) string {
	return fmt.Sprintf(`
resource "vault_terraform_cloud_secret_backend" "test" {
  backend                    = "%s"
  token                      = "%s"
  explicit_max_ttl           = "%d"
  rotation_period            = "%d"
  rotation_schedule          = "%s"
  rotation_window            = "%d"
  disable_automated_rotation = %t
}`, backend, token, explicitMaxTTL, period, schedule, window, disable)
}

func testTerraformCloudSecretBackend_initialConfig(path, token string) string {
	return fmt.Sprintf(`
resource "vault_terraform_cloud_secret_backend" "test" {
  backend = "%s"
  description = "test description"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds = 86400
  token = "%s"
}`, path, token)
}

func testTerraformCloudSecretBackend_updateConfig(path, token string) string {
	return fmt.Sprintf(`
resource "vault_terraform_cloud_secret_backend" "test" {
  backend = "%s"
  description = "test description"
  address = "https://app.terraform.io/not"
  token = "%s"
  base_path = "/not/api/v2/"
}`, path, token)
}

func testTerraformCloudSecretBackend_tokenWoInitialConfig(path, token string) string {
	return fmt.Sprintf(`
resource "vault_terraform_cloud_secret_backend" "test" {
  backend = "%s"
  token_wo = "%s"
  token_wo_version = 1
}`, path, token)
}

func testTerraformCloudSecretBackend_tokenWoUpdatedConfig(path, token string, version int) string {
	return fmt.Sprintf(`
resource "vault_terraform_cloud_secret_backend" "test" {
  backend           = "%s"
  token_wo          = "%s"
  token_wo_version  = %d
}`, path, token, version)
}

func testTerraformCloudSecretBackend_tokenWoNoVersion(path string, version int) string {
	return fmt.Sprintf(`
resource "vault_terraform_cloud_secret_backend" "test" {
  backend           = "%s"
  token_wo_version  = %d
}`, path, version)
}

func testTerraformCloudSecretBackend_tokenWoEmptyString(path string, version int) string {
	return fmt.Sprintf(`
resource "vault_terraform_cloud_secret_backend" "test" {
  backend           = "%s"
  token_wo          = ""
  token_wo_version  = %d
}`, path, version)
}

// testProviderMeta spins up an httptest server with the given handler, creates
// a Vault API client pointed at it, and returns a *provider.ProviderMeta
// wired to that client (skip_get_vault_version=true).
func testProviderMeta(t *testing.T, handler http.HandlerFunc) interface{} {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	s := map[string]*schema.Schema{
		consts.FieldAddress: {
			Type:     schema.TypeString,
			Required: true,
		},
		"token": {
			Type:     schema.TypeString,
			Required: true,
		},
		consts.FieldSkipGetVaultVersion: {
			Type:     schema.TypeBool,
			Optional: true,
			Default:  true,
		},
	}

	d := schema.TestResourceDataRaw(t, s, map[string]interface{}{
		consts.FieldAddress:             srv.URL,
		"token":                         "test-token",
		consts.FieldSkipGetVaultVersion: true,
	})

	meta, err := provider.NewProviderMeta(d)
	if err != nil {
		t.Fatalf("NewProviderMeta: %v", err)
	}

	return meta
}

// testTokenLookupHandler returns a minimal http.HandlerFunc that satisfies the
// token setup calls (lookup-self + create) made by setClient().
func testTokenLookupHandler(next func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/token/lookup-self":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"id": "test-token", "policies": []string{"root"},
				},
			})
		case "/v1/auth/token/create":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token": "child-test-token", "policies": []string{"root"},
					"lease_duration": 3600, "renewable": true,
				},
			})
		default:
			next(w, r)
		}
	}
}

// TestTerraformCloudSecretBackendRead_configNotFound verifies that when
// /config returns 404 with no data, ParseRawResponseAndCloseBody returns
// (nil, nil) and the existing secret == nil check removes the resource from
// state cleanly with no error diagnostics.
func TestTerraformCloudSecretBackendRead_configNotFound(t *testing.T) {
	const backend = "terraform"

	meta := testProviderMeta(t, testTokenLookupHandler(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/sys/mounts/" + backend:
			json.NewEncoder(w).Encode(map[string]interface{}{
				"type": "terraform", "description": "", "options": map[string]interface{}{},
				"config": map[string]interface{}{"default_lease_ttl": 0, "max_lease_ttl": 0, "force_no_cache": false},
			})
		case "/v1/" + backend + "/config":
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"errors": []string{"No secret engine mount at " + backend + "/"},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{"not found"}})
		}
	}))

	rsc := terraformCloudSecretBackendResource()
	d := rsc.TestResourceData()
	d.SetId(backend)
	if err := d.Set(consts.FieldBackend, backend); err != nil {
		t.Fatal(err)
	}

	diags := terraformCloudSecretBackendRead(context.Background(), d, meta)
	if diags.HasError() {
		t.Fatalf("expected no error on 404 config read, got: %v", diags)
	}
	if d.Id() != "" {
		t.Errorf("expected resource removed from state, got id=%q", d.Id())
	}
}

// TestTerraformCloudSecretBackendRead_configNon404Error verifies that a
// non-404 error on the /config read surfaces as a diagnostic error.
func TestTerraformCloudSecretBackendRead_configNon404Error(t *testing.T) {
	const backend = "terraform"

	meta := testProviderMeta(t, testTokenLookupHandler(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/sys/mounts/" + backend:
			json.NewEncoder(w).Encode(map[string]interface{}{
				"type": "terraform", "description": "", "options": map[string]interface{}{},
				"config": map[string]interface{}{"default_lease_ttl": 0, "max_lease_ttl": 0, "force_no_cache": false},
			})
		case "/v1/" + backend + "/config":
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"errors": []string{"internal server error"},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{"not found"}})
		}
	}))

	rsc := terraformCloudSecretBackendResource()
	d := rsc.TestResourceData()
	d.SetId(backend)
	if err := d.Set(consts.FieldBackend, backend); err != nil {
		t.Fatal(err)
	}

	diags := terraformCloudSecretBackendRead(context.Background(), d, meta)
	if !diags.HasError() {
		t.Fatal("expected a diagnostic error on 500 config read, got none")
	}
}

// TestTerraformCloudSecretBackendDelete_mountIs404 verifies that a 404 on
// unmount (mount already deleted out-of-band) removes the resource from state
// cleanly with no error diagnostics.
func TestTerraformCloudSecretBackendDelete_mountIs404(t *testing.T) {
	const backend = "terraform"

	meta := testProviderMeta(t, testTokenLookupHandler(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/mounts/"+backend && r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"errors": []string{fmt.Sprintf("No secret engine mount at %s/", backend)},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{"not found"}})
	}))

	rsc := terraformCloudSecretBackendResource()
	d := rsc.TestResourceData()
	d.SetId(backend)

	diags := terraformCloudSecretBackendDelete(context.Background(), d, meta)
	if diags.HasError() {
		t.Fatalf("expected no error on 404 unmount, got: %v", diags)
	}
	if d.Id() != "" {
		t.Errorf("expected resource removed from state, got id=%q", d.Id())
	}
}

// TestTerraformCloudSecretBackendDelete_mountNon404Error verifies that a
// non-404 error on unmount surfaces as a diagnostic error.
func TestTerraformCloudSecretBackendDelete_mountNon404Error(t *testing.T) {
	const backend = "terraform"

	meta := testProviderMeta(t, testTokenLookupHandler(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/mounts/"+backend && r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"errors": []string{"internal server error"},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{"not found"}})
	}))

	rsc := terraformCloudSecretBackendResource()
	d := rsc.TestResourceData()
	d.SetId(backend)

	diags := terraformCloudSecretBackendDelete(context.Background(), d, meta)
	if !diags.HasError() {
		t.Fatal("expected a diagnostic error on 500 unmount, got none")
	}
}
