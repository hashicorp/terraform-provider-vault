// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config_test

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-provider-vault/acctestutil"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
	"github.com/hashicorp/terraform-provider-vault/internal/vault/sys/config"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccControlGroupConfigResourceSchema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	schemaRequest := fwresource.SchemaRequest{}
	schemaResponse := &fwresource.SchemaResponse{}

	config.NewControlGroupConfigResource().Schema(ctx, schemaRequest, schemaResponse)
	if schemaResponse.Diagnostics.HasError() {
		t.Fatalf("Schema method diagnostics: %+v", schemaResponse.Diagnostics)
	}

	diagnostics := schemaResponse.Schema.ValidateImplementation(ctx)
	if diagnostics.HasError() {
		t.Fatalf("Schema validation diagnostics: %+v", diagnostics)
	}

	maxTTLAttr, ok := schemaResponse.Schema.Attributes[consts.FieldMaxTTL]
	if !ok {
		t.Fatalf("schema is missing %q", consts.FieldMaxTTL)
	}

	maxTTLStringAttr, ok := maxTTLAttr.(resourceschema.StringAttribute)
	if !ok {
		t.Fatalf("schema attribute %q has unexpected type: %T", consts.FieldMaxTTL, maxTTLAttr)
	}

	if !maxTTLStringAttr.Optional {
		t.Fatalf("schema attribute %q must be optional", consts.FieldMaxTTL)
	}

	if maxTTLStringAttr.Computed {
		t.Fatalf("schema attribute %q must not be computed when default is empty", consts.FieldMaxTTL)
	}
}

func TestAccControlGroupConfigResource(t *testing.T) {
	resourceName := "vault_config_control_group.test"

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccControlGroupConfig("24h"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "24h"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				Config: testAccControlGroupConfig("48h"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "48h"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldMaxTTL),
		},
	})
}

func TestAccControlGroupConfigResourceNamespace(t *testing.T) {
	ns := acctest.RandomWithPrefix("ns")
	resourceName := "vault_config_control_group.test"
	configNS := testAccControlGroupConfigNS(ns, "24h")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: configNS,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldNamespace, ns),
					resource.TestCheckResourceAttr(resourceName, consts.FieldMaxTTL, "24h"),
				),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			testutil.GetImportTestStepNS(t, ns, resourceName, configNS, consts.FieldMaxTTL),
			testutil.GetImportTestStepNSCleanup(t, configNS),
		},
	})
}

func TestAccControlGroupConfigResourceInvalidFormat(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctestutil.TestAccPreCheck(t)
			acctestutil.TestEntPreCheck(t)
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccControlGroupConfig("invalid-time-format"),
				ExpectError: regexp.MustCompile("Invalid duration string"),
			},
			{
				Config:      testAccControlGroupConfig("24x"),
				ExpectError: regexp.MustCompile("Invalid duration string"),
			},
			{
				Config:      testAccControlGroupConfig("not-a-duration"),
				ExpectError: regexp.MustCompile("Invalid duration string"),
			},
		},
	})
}

func testAccControlGroupConfig(maxTTL string) string {
	return fmt.Sprintf(`
resource "vault_config_control_group" "test" {
  max_ttl = %q
}
`, maxTTL)
}

func testAccControlGroupConfigNS(ns, maxTTL string) string {
	return fmt.Sprintf(`
resource "vault_namespace" "ns1" {
  path = %q
}

resource "vault_config_control_group" "test" {
  namespace = vault_namespace.ns1.path
  max_ttl = %q
}
`, ns, maxTTL)
}
