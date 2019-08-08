package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

func TestDataSourcePolicyDocument(t *testing.T) {
	t.Skip("this test fails intermittently and needs to be fixed")
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
    path                = "secret/test1/*"
    capabilities        = ["create", "read", "update", "delete", "list"]
    description         = "test rule 1"
    required_parameters = ["test_param1"]

    allowed_parameter {
      key   = "eggs"
      value = ["foo", "bar"]
    }

    allowed_parameter {
      key   = "spam"
      value = ["eggs"]
    }

    denied_parameter {
      key   = "*"
      value = ["spam"]
    }

    max_wrapping_ttl = "1h"
  }

  rule {
    path                = "secret/test2/*"
    capabilities        = ["read", "list"]
    description         = "test rule 2"
    required_parameters = ["test_param2"]

    allowed_parameter {
      key   = "all"
      value = []
    }

    denied_parameter {
      key   = "*"
      value = []
    }

    min_wrapping_ttl = "1s"
  }

  rule {
    path                = "secret/test3/"
    capabilities        = ["read", "list"]
  }
}
`

var testResultPolicyHCLDocument = `# test rule 1
path "secret/test1/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
  required_parameters = ["test_param1"]
  allowed_parameters = {
    "eggs" = ["foo", "bar"]
    "spam" = ["eggs"]
  }
  denied_parameters = {
    "*" = ["spam"]
  }
  max_wrapping_ttl = "1h"
}

# test rule 2
path "secret/test2/*" {
  capabilities = ["read", "list"]
  required_parameters = ["test_param2"]
  allowed_parameters = {
    "all" = []
  }
  denied_parameters = {
    "*" = []
  }
  min_wrapping_ttl = "1s"
}

path "secret/test3/" {
  capabilities = ["read", "list"]
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

	if got, want := iState.Attributes["hcl"], testResultPolicyHCLDocument; got != want {
		return fmt.Errorf("hcl contains %s; want %s", got, want)
	}

	return nil
}
