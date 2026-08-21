// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

const resourceName = "vault_mount.test"

// Case 1: kv v1 import baseline.
func TestAccMount_importBasic(t *testing.T) {
	path := "test-" + acctest.RandString(10)
	cfg := testMountConfig{
		path:      path,
		mountType: "kv",
		version:   "1",
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{
				Config: testResourceMount_initialConfig(cfg),
				Check:  testResourceMount_initialCheck(cfg),
			},
			testutil.GetImportTestStep(resourceName, false, nil, "type", "options"),
		},
	})
}

// Case 2: non-kv mount (pki). Suppressor must not fire for unrelated types.
func TestAccMount_importNonKV(t *testing.T) {
	path := "test-" + acctest.RandString(10)
	cfg := fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "pki"
}`, path)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{Config: cfg},
			testutil.GetImportTestStep(resourceName, false, nil),
			{Config: cfg, PlanOnly: true},
		},
	})
}

// Case 3 (core bug): vault returns kv+version=2 on import, config says kv-v2.
// Suppressors must fire — no ForceNew, no destroy.
func TestAccMount_importKVV2(t *testing.T) {
	path := "test-" + acctest.RandString(10)
	cfg := fmt.Sprintf(`
resource "vault_mount" "test" {
  path                      = "%s"
  type                      = "kv-v2"
  description               = "kv-v2 import test"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 36000
}`, path)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{Config: cfg},
			testutil.GetImportTestStep(resourceName, false, nil, "type", "options"),
			{Config: cfg, PlanOnly: true},
		},
	})
}

// Case 4: config says kv+version=2 (explicit raw form). State matches directly, no suppressor needed.
func TestAccMount_importKVV2_explicitOptions(t *testing.T) {
	path := "test-" + acctest.RandString(10)
	cfg := fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "kv"
  options = {
    version = "2"
  }
}`, path)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{Config: cfg},
			testutil.GetImportTestStep(resourceName, false, nil, "type", "options"),
			{Config: cfg, PlanOnly: true},
		},
	})
}

// Case 5: kv v1 mount. Suppressor must not fire — no options.version=2.
func TestAccMount_importKVV1_noSuppress(t *testing.T) {
	path := "test-" + acctest.RandString(10)
	cfg := fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "kv"
  options = {
    version = "1"
  }
}`, path)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{Config: cfg},
			testutil.GetImportTestStep(resourceName, false, nil, "type", "options"),
			{Config: cfg, PlanOnly: true},
		},
	})
}

// Case 6: v1 mount imported with kv-v2 config. Suppressor checks options.version=2 — absent on v1 — so real diff surfaces.
func TestAccMount_importKVV1_misconfiguredAsKVV2(t *testing.T) {
	path := "test-" + acctest.RandString(10)

	v1Cfg := fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "kv"
  options = {
    version = "1"
  }
}`, path)

	v2Cfg := fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "kv-v2"
}`, path)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{Config: v1Cfg},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: false,
			},
			{
				Config:             v2Cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Case 7: kv-v2 with redundant explicit options.version=2. Should behave the same as case 3.
func TestAccMount_importKVV2_redundantOptions(t *testing.T) {
	path := "test-" + acctest.RandString(10)
	cfg := fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "kv-v2"
  options = {
    version = "2"
  }
}`, path)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{Config: cfg},
			testutil.GetImportTestStep(resourceName, false, nil, "type", "options"),
			{Config: cfg, PlanOnly: true},
		},
	})
}

// Case 8: state=kv-v2, config changes to kv+version=2. Suppressor is one-way only, so ForceNew surfaces.
func TestAccMount_importKVV2_stateAsKVV2_configAsKV(t *testing.T) {
	path := "test-" + acctest.RandString(10)

	v2Cfg := fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "kv-v2"
}`, path)

	kvCfg := fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "kv"
  options = {
    version = "2"
  }
}`, path)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{Config: v2Cfg},
			{
				Config:             kvCfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// update an unrelated field on kv-v2 — type must stay kv-v2, no perpetual drift.
func TestAccMount_updateKVV2_noTypeDrift(t *testing.T) {
	path := "test-" + acctest.RandString(10)
	cfg1 := fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "kv-v2"
  description = "before"
}`, path)

	cfg2 := fmt.Sprintf(`
resource "vault_mount" "test" {
  path        = "%s"
  type        = "kv-v2"
  description = "after"
}`, path)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			{Config: cfg1},
			{
				Config: cfg2,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "description", "after"),
					resource.TestCheckResourceAttr(resourceName, "type", "kv-v2"),
				),
			},
			{Config: cfg2, PlanOnly: true},
		},
	})
}
