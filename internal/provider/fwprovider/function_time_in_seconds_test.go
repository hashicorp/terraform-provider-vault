// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package fwprovider_test

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/hashicorp/terraform-provider-vault/internal/providertest"
)

func TestTimeInSeconds_valid(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_8_0),
		},
		ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `output "test" { value = provider::vault::time_in_seconds("1h") }`,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectKnownOutputValue("test", knownvalue.Int64Exact(3600)),
					},
				},
			},
			{
				Config: `output "test" { value = provider::vault::time_in_seconds("60m") }`,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				Config: `output "test" { value = provider::vault::time_in_seconds("3600s") }`,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				Config: `output "test" { value = provider::vault::time_in_seconds("3600000ms") }`,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				Config: `output "test" { value = provider::vault::time_in_seconds("3600") }`,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			{
				Config: `output "test" { value = provider::vault::time_in_seconds("1d") }`,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectKnownOutputValue("test", knownvalue.Int64Exact(86400)),
					},
				},
			},
			{
				Config: `output "test" { value = provider::vault::time_in_seconds("0s") }`,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectKnownOutputValue("test", knownvalue.Int64Exact(0)),
					},
				},
			},
		},
	})
}

func TestTimeInSeconds_invalid(t *testing.T) {
	cases := []struct {
		name  string
		input string
		err   *regexp.Regexp
	}{
		{
			name:  "letters",
			input: "abcdef",
			err:   regexp.MustCompile(`"abcdef" is not a valid duration string`),
		},
		{
			name:  "empty",
			input: "",
			err:   regexp.MustCompile(`duration must not be empty`),
		},
		{
			name:  "negative",
			input: "-1h",
			err:   regexp.MustCompile(`"-1h"[\s\S]*must not be negative`),
		},
		{
			name:  "fractional seconds",
			input: "1.5s",
			err:   regexp.MustCompile(`"1\.5s"[\s\S]*must be a whole number of seconds`),
		},
		{
			name:  "milliseconds",
			input: "500ms",
			err:   regexp.MustCompile(`"500ms"[\s\S]*must be a whole number of seconds`),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resource.UnitTest(t, resource.TestCase{
				TerraformVersionChecks: []tfversion.TerraformVersionCheck{
					tfversion.SkipBelow(tfversion.Version1_8_0),
				},
				ProtoV5ProviderFactories: providertest.ProtoV5ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config:      `output "test" { value = provider::vault::time_in_seconds("` + tc.input + `") }`,
						ExpectError: tc.err,
					},
				},
			})
		})
	}
}
