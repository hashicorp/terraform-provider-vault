package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccIdentityOIDCAssignment(t *testing.T) {
	name := acctest.RandomWithPrefix("test-scope")
	resourceName := "vault_identity_oidc_assignment.test"

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccCheckIdentityEntityDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityOIDCAssignmentConfig_basic(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "group_ids.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "group_ids.0", "groupid1"),
					resource.TestCheckResourceAttr(resourceName, "group_ids.1", "groupid2"),
					resource.TestCheckResourceAttr(resourceName, "entity_ids.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "entity_ids.0", "entityid1"),
					resource.TestCheckResourceAttr(resourceName, "entity_ids.1", "entityid2"),
				),
			},
			{
				Config: testAccIdentityOIDCAssignmentConfig_update(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "group_ids.#", "3"),
					resource.TestCheckResourceAttr(resourceName, "group_ids.0", "groupid1"),
					resource.TestCheckResourceAttr(resourceName, "group_ids.1", "groupid2"),
					resource.TestCheckResourceAttr(resourceName, "group_ids.2", "groupid3"),
					resource.TestCheckResourceAttr(resourceName, "entity_ids.#", "4"),
					resource.TestCheckResourceAttr(resourceName, "entity_ids.0", "entityid1"),
					resource.TestCheckResourceAttr(resourceName, "entity_ids.1", "entityid2"),
					resource.TestCheckResourceAttr(resourceName, "entity_ids.2", "entityid3"),
					resource.TestCheckResourceAttr(resourceName, "entity_ids.3", "entityid4"),
				),
			},
		},
	})
}

func TestLowercaseIDs(t *testing.T) {
	tests := []struct {
		name           string
		input          interface{}
		expectedOutput string
	}{
		{
			name:           "basic",
			input:          []string{"TestId1", "testID2"},
			expectedOutput: "testid1 testid2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := lowercaseIDs(tt.input)
			if output != tt.expectedOutput {
				t.Fatalf("expected string %q, got %q", tt.expectedOutput, output)
			}
		})
	}
}

func testAccIdentityOIDCAssignmentConfig_basic(name string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_assignment" "test" {
  name       = "%s"
  group_ids  = ["groupId1", "GroupID2"]
  entity_ids = ["entityID1", "EntityId2"]
}`, name)
}

func testAccIdentityOIDCAssignmentConfig_update(name string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc_assignment" "test" {
  name       = "%s"
  group_ids  = ["groupid1", "groupid2", "groupid3"]
  entity_ids = ["entityid1", "entityid2", "entityid3", "entityid4"]
}`, name)
}
