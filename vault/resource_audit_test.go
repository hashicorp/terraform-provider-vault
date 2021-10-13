package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

func TestResourceAudit(t *testing.T) {
	path := "example-" + acctest.RandString(10)
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testResourceAudit_initialConfig(path),
				Check:  testResourceAudit_initialCheck(path),
			},
		},
	})
}

func testResourceAudit_initialConfig(path string) string {
	return fmt.Sprintf(`
resource "vault_audit" "test" {
	path = "%s"
	type = "file"
	description = "Example file audit for vault"
	local = true
	options = {
		path = "stdout"
	}
}
`, path)
}

func testResourceAudit_initialCheck(expectedPath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources["vault_audit.test"]
		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		path := instanceState.ID

		if path != instanceState.Attributes["path"] {
			return fmt.Errorf("id %q doesn't match path %q", path, instanceState.Attributes["path"])
		}

		if path != expectedPath {
			return fmt.Errorf("unexpected path %q, expected %q", path, expectedPath)
		}

		audit, err := findAudit(path)
		if err != nil {
			return fmt.Errorf("error reading back mount %q: %s", path, err)
		}

		if wanted := "Example file audit for vault"; audit.Description != wanted {
			return fmt.Errorf("description is %v; wanted %v", audit.Description, wanted)
		}

		if wanted := "file"; audit.Type != wanted {
			return fmt.Errorf("type is %v; wanted %v", audit.Type, wanted)
		}

		if wanted := true; audit.Local != wanted {
			return fmt.Errorf("local is %v; wanted %v", audit.Local, wanted)
		}

		if wanted := "stdout"; audit.Options["path"] != wanted {
			return fmt.Errorf("log path is %v; wanted %v", audit.Options["path"], wanted)
		}

		return nil
	}
}

func findAudit(path string) (*api.Audit, error) {
	client := testProvider.Meta().(*api.Client)

	path = path + "/"

	audits, err := client.Sys().ListAudit()
	if err != nil {
		return nil, err
	}

	if audits[path] != nil {
		return audits[path], nil
	}

	return nil, fmt.Errorf("unable to find audit %s in Vault; current list: %v", path, audits)
}
