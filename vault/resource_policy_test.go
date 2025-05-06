// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestResourcePolicy(t *testing.T) {
	name := acctest.RandomWithPrefix("test-")
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck:          func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourcePolicy_initialConfig(name),
				Check:  testResourcePolicy_initialCheck(name),
			},
			{
				Config: testResourcePolicy_updateConfig,
				Check:  testResourcePolicy_updateCheck,
			},
		},
	})
}

func testResourcePolicy_initialConfig(name string) string {
	return fmt.Sprintf(`
resource "vault_policy" "test" {
	name = "%s"
	policy = <<EOT
path "secret/*" {
	policy = "read"
}
EOT
}
`, name)
}

func testResourcePolicy_initialCheck(expectedName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_policy.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		name := instanceState.ID

		if name != instanceState.Attributes["name"] {
			return fmt.Errorf("id %q doesn't match name %q", name, instanceState.Attributes["name"])
		}

		if name != expectedName {
			return fmt.Errorf("unexpected policy name %q, expected %q", name, expectedName)
		}

		client, e := provider.GetClient(instanceState, testProvider.Meta())
		if e != nil {
			return e
		}

		policy, err := client.Sys().GetPolicy(name)
		if err != nil {
			return fmt.Errorf("error reading back policy: %s", err)
		}

		if got, want := policy, "path \"secret/*\" {\n\tpolicy = \"read\"\n}\n"; got != want {
			return fmt.Errorf("policy data is %q; want %q", got, want)
		}

		return nil
	}
}

var testResourcePolicy_updateConfig = `

resource "vault_policy" "test" {
	name = "dev-team"
	policy = <<EOT
path "secret/*" {
	policy = "write"
}
EOT
}

`

func testResourcePolicy_updateCheck(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["vault_policy.test"]
	instanceState := resourceState.Primary

	name := instanceState.ID

	client, e := provider.GetClient(instanceState, testProvider.Meta())
	if e != nil {
		return e
	}

	if name != instanceState.Attributes["name"] {
		return fmt.Errorf("id doesn't match name")
	}

	if name != "dev-team" {
		return fmt.Errorf("unexpected policy name")
	}

	policy, err := client.Sys().GetPolicy(name)
	if err != nil {
		return fmt.Errorf("error reading back policy: %s", err)
	}

	if got, want := policy, "path \"secret/*\" {\n\tpolicy = \"write\"\n}\n"; got != want {
		return fmt.Errorf("policy data is %q; want %q", got, want)
	}

	return nil
}
