// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"regexp"
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
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourcePolicy_initialConfig(name),
				Check:  testResourcePolicy_initialCheck(name),
			},
			{
				ResourceName:            "vault_policy.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"allow_overwrite"},
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

func TestResourcePolicy_defaultOverwrite(t *testing.T) {
	name := acctest.RandomWithPrefix("test-")
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				PreConfig: func() {
					client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()
					if err := client.Sys().PutPolicy(name, "path \"secret/*\" { capabilities = [\"read\"] }"); err != nil {
						t.Fatalf("failed to pre-create policy %q: %s", name, err)
					}
				},
				Config: testResourcePolicy_defaultOverwriteConfig(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_policy.test", "name", name),
				),
			},
		},
	})
}

func TestResourcePolicy_allowOverwrite(t *testing.T) {
	name := acctest.RandomWithPrefix("test-")
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				PreConfig: func() {
					client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()
					if err := client.Sys().PutPolicy(name, "path \"secret/*\" { capabilities = [\"read\"] }"); err != nil {
						t.Fatalf("failed to pre-create policy %q: %s", name, err)
					}
				},
				Config: testResourcePolicy_allowOverwriteConfig(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_policy.test", "name", name),
				),
			},
		},
	})
}

func TestResourcePolicy_noOverwrite(t *testing.T) {
	name := acctest.RandomWithPrefix("test-")
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				PreConfig: func() {
					client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()
					if err := client.Sys().PutPolicy(name, "path \"secret/*\" { capabilities = [\"read\"] }"); err != nil {
						t.Fatalf("failed to pre-create policy %q: %s", name, err)
					}
				},
				Config:      testResourcePolicy_noOverwriteConfig(name),
				ExpectError: regexp.MustCompile(`already exists`),
			},
		},
	})
}

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

func testResourcePolicy_defaultOverwriteConfig(name string) string {
	return fmt.Sprintf(`
resource "vault_policy" "test" {
  name            = "%s"
  policy          = <<EOT
path "secret/*" {
  capabilities = ["read"]
}
EOT
}
`, name)
}

func testResourcePolicy_allowOverwriteConfig(name string) string {
	return fmt.Sprintf(`
resource "vault_policy" "test" {
  name            = "%s"
  allow_overwrite = true
  policy          = <<EOT
path "secret/*" {
  capabilities = ["read"]
}
EOT
}
`, name)
}

func testResourcePolicy_noOverwriteConfig(name string) string {
	return fmt.Sprintf(`
resource "vault_policy" "test" {
  name            = "%s"
  allow_overwrite = false
  policy          = <<EOT
path "secret/*" {
  capabilities = ["read"]
}
EOT
}
`, name)
}
