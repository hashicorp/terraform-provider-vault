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

// Case 1 baseline: plain kv v1 import
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
			// case 1: state=kv, config=kv, no suppressor should fire
			testutil.GetImportTestStep(resourceName, false, nil, "type", "options"),
		},
	})
}

// Case 2: non-kv mount (pki). Suppressor must never fire for unrelated types.
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
			{
				Config: cfg,
			},
			testutil.GetImportTestStep(resourceName, false, nil),
			// plan must be clean — suppressor did not touch a non-kv type
			{
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}

// Case 3 (core bug): config says kv-v2, vault returns kv+version=2 on import.
// Suppressors must fire — plan should show no diff, no destroy.
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
			// apply so the mount exists in vault
			{
				Config: cfg,
			},
			// import — state lands as kv+version=2, config says kv-v2
			// suppressors fire, no ForceNew, no destroy
			testutil.GetImportTestStep(resourceName, false, nil, "type", "options"),
			// plan after import must be clean
			{
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}

// Case 4: config says kv+version=2 (explicit raw form). Import lands same way.
// No suppressor needed — state already matches config.
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
			{
				Config: cfg,
			},
			// state=kv+version=2, config=kv+version=2 — direct match, no suppressor
			testutil.GetImportTestStep(resourceName, false, nil, "type", "options"),
			// plan after import must be clean
			{
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}

// Case 5: real kv v1 mount. Suppressor must NOT fire — no options.version=2.
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
			{
				Config: cfg,
			},
			testutil.GetImportTestStep(resourceName, false, nil, "type", "options"),
			// plan must be clean — suppressor did not fire, no spurious diff
			{
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}

// Case 6 (critical inverse): real kv v1 mount but config says kv-v2.
// Suppressor checks options.version=2 — not present on v1 — so it does NOT suppress.
// Plan must show a real diff (ForceNew), not silently pass.
func TestAccMount_importKVV1_misconfiguredAsKVV2(t *testing.T) {
	path := "test-" + acctest.RandString(10)

	// create as v1
	v1Cfg := fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "kv"
  options = {
    version = "1"
  }
}`, path)

	// config incorrectly claims kv-v2
	v2Cfg := fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "kv-v2"
}`, path)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		Steps: []resource.TestStep{
			// create the mount as v1
			{
				Config: v1Cfg,
			},
			// import using v2 config — suppressor should NOT fire, plan shows diff
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: false, // we expect mismatch
			},
			// plan with v2 config must show a real ForceNew diff
			{
				Config:             v2Cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Case 8 (reverse direction safety): state=kv-v2 (after a normal apply+read), config changes
// to kv+version=2. Suppressor must NOT fire — the user explicitly changed the type string,
// so ForceNew is correct and expected.
func TestAccMount_importKVV2_stateAsKVV2_configAsKV(t *testing.T) {
	path := "test-" + acctest.RandString(10)

	// create as kv-v2; after apply+read, readMount normalises state to type=kv-v2
	v2Cfg := fmt.Sprintf(`
resource "vault_mount" "test" {
  path = "%s"
  type = "kv-v2"
}`, path)

	// user rewrites config to the raw form — state=kv-v2 vs config=kv: real diff
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
			{
				Config: v2Cfg,
			},
			// state=kv-v2, config=kv — suppressor does not fire (one-way only),
			// so ForceNew surfaces. this is the correct and expected behaviour.
			{
				Config:             kvCfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Case 7: kv-v2 with redundant explicit options.version=2. Should work same as case 3.
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
			{
				Config: cfg,
			},
			testutil.GetImportTestStep(resourceName, false, nil, "type", "options"),
			{
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}

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
			// confirm next plan is clean — no perpetual drift
			{Config: cfg2, PlanOnly: true},
		},
	})
}
