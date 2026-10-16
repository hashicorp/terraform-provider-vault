// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package tune_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

func TestAccAuthTune(t *testing.T) {
	path := acctest.RandomWithPrefix("auth-tune")
	resourceName := "vault_auth_tune.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckAuthTuneDestroyed(path),
		Steps: []resource.TestStep{
			{
				Config: testAccAuthTuneConfig(path, "200s", "batch", false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl", "200s"),
					resource.TestCheckResourceAttr(resourceName, "token_type", "batch"),
					resource.TestCheckNoResourceAttr(resourceName, "max_lease_ttl"),
					resource.TestCheckNoResourceAttr(resourceName, "listing_visibility"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				Config: testAccAuthTuneConfig(path, "10m", "", true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl", "10m"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl", "20m"),
					resource.TestCheckNoResourceAttr(resourceName, "token_type"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				Config: testAccAuthTuneConfigTTLReset(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "token_type", "batch"),
					resource.TestCheckNoResourceAttr(resourceName, "default_lease_ttl"),
					resource.TestCheckNoResourceAttr(resourceName, "max_lease_ttl"),
					testAccCheckAuthTuneTTLsMatchSystem(path),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				Config: testAccAuthTuneConfigFull(path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "default_lease_ttl", "10m"),
					resource.TestCheckResourceAttr(resourceName, "max_lease_ttl", "20m"),
					resource.TestCheckResourceAttr(resourceName, "token_type", "batch"),
					resource.TestCheckResourceAttr(resourceName, "listing_visibility", "unauth"),
					resource.TestCheckResourceAttr(resourceName, "audit_non_hmac_request_keys.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "audit_non_hmac_request_keys.0", "request-key"),
					resource.TestCheckResourceAttr(resourceName, "audit_non_hmac_response_keys.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "audit_non_hmac_response_keys.0", "response-key"),
					resource.TestCheckResourceAttr(resourceName, "passthrough_request_headers.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "passthrough_request_headers.0", "X-Custom"),
					resource.TestCheckResourceAttr(resourceName, "allowed_response_headers.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "allowed_response_headers.0", "X-Response"),
					resource.TestCheckResourceAttr(resourceName, "user_lockout_config.lockout_threshold", "5"),
					resource.TestCheckResourceAttr(resourceName, "user_lockout_config.lockout_duration", "10m"),
					resource.TestCheckResourceAttr(resourceName, "user_lockout_config.lockout_counter_reset", "15m"),
					resource.TestCheckResourceAttr(resourceName, "user_lockout_config.lockout_disable", "true"),
					resource.TestCheckNoResourceAttr(resourceName, "plugin_version"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionUpdate),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				ResourceName:                         resourceName,
				ImportState:                          true,
				ImportStateIdFunc:                    testAccAuthTuneImportID(resourceName),
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "path",
			},
			{
				Config: testAccAuthTuneConfigDestroyed(path),
				Check:  testAccCheckAuthTuneCleared(path),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(resourceName, plancheck.ResourceActionDestroy),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
		},
	})
}

func TestAccAuthTune_namespace(t *testing.T) {
	ns := acctest.RandomWithPrefix("auth-tune-ns")
	path := acctest.RandomWithPrefix("auth-tune")
	resourceName := "vault_auth_tune.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctestutil.TestEntPreCheck(t) },
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccAuthTuneNamespaceConfig(ns, path),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "namespace", ns),
					resource.TestCheckResourceAttr(resourceName, "path", path),
					resource.TestCheckResourceAttr(resourceName, "token_type", "batch"),
					resource.TestCheckResourceAttr(resourceName, "listing_visibility", "unauth"),
				),
			},
		},
	})
}

func testAccAuthTuneImportID(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		return rs.Primary.Attributes["path"], nil
	}
}

func testAccAuthTuneConfigTTLReset(path string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
  type = "userpass"
  path = %q
}

resource "vault_auth_backend" "baseline" {
  type = "approle"
  path = "%s-baseline"
}

resource "vault_auth_tune" "test" {
  path       = vault_auth_backend.test.path
  token_type = "batch"
}
`, path, path)
}

func testAccVaultClient() (*api.Client, error) {
	cfg := api.DefaultConfig()
	if err := cfg.ReadEnvironment(); err != nil {
		return nil, err
	}
	return api.NewClient(cfg)
}

func testAccCheckAuthTuneTTLsMatchSystem(mountPath string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccVaultClient()
		if err != nil {
			return err
		}

		tuned, err := client.Sys().MountConfig("auth/" + mountPath)
		if err != nil {
			return fmt.Errorf("reading tuned mount: %w", err)
		}
		baseline, err := client.Sys().MountConfig("auth/" + mountPath + "-baseline")
		if err != nil {
			return fmt.Errorf("reading baseline mount: %w", err)
		}
		if tuned.DefaultLeaseTTL != baseline.DefaultLeaseTTL {
			return fmt.Errorf("default_lease_ttl = %ds, system default = %ds", tuned.DefaultLeaseTTL, baseline.DefaultLeaseTTL)
		}
		if tuned.MaxLeaseTTL != baseline.MaxLeaseTTL {
			return fmt.Errorf("max_lease_ttl = %ds, system default = %ds", tuned.MaxLeaseTTL, baseline.MaxLeaseTTL)
		}
		return nil
	}
}

func testAccCheckAuthTuneCleared(mountPath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if err := testAccCheckAuthTuneTTLsMatchSystem(mountPath)(s); err != nil {
			return err
		}

		client, err := testAccVaultClient()
		if err != nil {
			return err
		}
		tuned, err := client.Logical().Read("sys/mounts/auth/" + mountPath + "/tune")
		if err != nil || tuned == nil || tuned.Data == nil {
			return fmt.Errorf("reading tuned mount: %w", err)
		}
		baseline, err := client.Logical().Read("sys/mounts/auth/" + mountPath + "-baseline/tune")
		if err != nil || baseline == nil || baseline.Data == nil {
			return fmt.Errorf("reading baseline mount: %w", err)
		}
		for _, key := range []string{"listing_visibility", "token_type"} {
			if got, want := tuneScalar(tuned.Data[key]), tuneScalar(baseline.Data[key]); got != want {
				return fmt.Errorf("%s = %q, system default = %q", key, got, want)
			}
		}
		return nil
	}
}

func testAccCheckAuthTuneDestroyed(mountPath string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		client, err := testAccVaultClient()
		if err != nil {
			return err
		}
		mount, err := client.Sys().GetAuth(mountPath)
		if err != nil {
			if mountutil.IsMountNotFoundError(err) || strings.Contains(err.Error(), "No secret engine mount") || strings.Contains(err.Error(), "No auth engine") {
				return nil
			}
			return fmt.Errorf("reading auth mount %q: %w", mountPath, err)
		}
		if mount != nil {
			return fmt.Errorf("auth mount %q still exists after destroy", mountPath)
		}
		return nil
	}
}

func tuneScalar(v interface{}) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func testAccAuthTuneConfigFull(path string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
  type = "userpass"
  path = %q
}

resource "vault_auth_tune" "test" {
  path                         = vault_auth_backend.test.path
  default_lease_ttl            = "10m"
  max_lease_ttl                = "20m"
  token_type                   = "batch"
  listing_visibility           = "unauth"
  audit_non_hmac_request_keys  = ["request-key"]
  audit_non_hmac_response_keys = ["response-key"]
  passthrough_request_headers  = ["X-Custom"]
  allowed_response_headers     = ["X-Response"]

  user_lockout_config {
    lockout_threshold     = "5"
    lockout_duration      = "10m"
    lockout_counter_reset = "15m"
    lockout_disable       = true
  }
}
`, path)
}

func testAccAuthTuneConfigDestroyed(path string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test" {
  type = "userpass"
  path = %q
}

resource "vault_auth_backend" "baseline" {
  type = "approle"
  path = "%s-baseline"
}
`, path, path)
}

func testAccAuthTuneNamespaceConfig(ns, path string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "test" {
  path = %q
}

resource "vault_auth_backend" "test" {
  namespace = vault_namespace.test.path
  type      = "userpass"
  path      = %q
}

resource "vault_auth_tune" "test" {
  namespace          = vault_namespace.test.path
  path               = vault_auth_backend.test.path
  token_type         = "batch"
  listing_visibility = "unauth"
}
`, ns, path)
}

func testAccAuthTuneConfig(path, defaultTTL, tokenType string, withMax bool) string {
	body := fmt.Sprintf(`
resource "vault_auth_backend" "test" {
  type = "userpass"
  path = %q
}

resource "vault_auth_tune" "test" {
  path              = vault_auth_backend.test.path
  default_lease_ttl = %q
`, path, defaultTTL)
	if tokenType != "" {
		body += fmt.Sprintf("  token_type        = %q\n", tokenType)
	}
	if withMax {
		body += "  max_lease_ttl     = \"20m\"\n"
	}
	body += "}\n"
	return body
}
