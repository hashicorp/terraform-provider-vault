package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

func TestDataSourcePolicyDocument(t *testing.T) {
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourcePolicyDocument_config,
				Check:  testDataSourcePolicyDocument_check,
			},
		},
	})

}

var testDataSourcePolicyDocument_config = `
data "vault_policy_document" "test" {
  rule {
    path = "secret/"
	capabilities = ["create", "read", "update", "delete", "list"]
	description = "test policy rule"
  }
}
`

func testDataSourcePolicyDocument_check(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["data.vault_policy_document.test"]
	if resourceState == nil {
		return fmt.Errorf("resource not found in state %v", s.Modules[0].Resources)
	}

	iState := resourceState.Primary
	if iState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	wantHCL := "# test policy rule\npath \"secret/\" {\n  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"]\n}"
	if got, want := iState.Attributes["hcl"], wantHCL; got != want {
		return fmt.Errorf("hcl contains %s; want %s", got, want)
	}

	return nil
}
