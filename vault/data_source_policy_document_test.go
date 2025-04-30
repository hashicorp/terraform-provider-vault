// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourcePolicyDocument(t *testing.T) {
	var p *schema.Provider
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
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
    path                  = "secret/test1/*"
    capabilities          = ["create", "read", "update", "delete", "list", "patch"]
    description           = "test rule 1"
    required_parameters   = ["test_param1"]
    subscribe_event_types = ["test_events1"]

    allowed_parameter {
      key   = "spam"
      value = ["eggs"]
    }

    allowed_parameter {
      key   = "eggs"
      value = ["foo", "bar"]
    }

    denied_parameter {
      key   = "b"
      value = ["eggs"]
    }

    denied_parameter {
      key   = "a"
      value = ["spam"]
    }

    max_wrapping_ttl = "1h"
  }

  rule {
    path                  = "secret/test2/*"
    capabilities          = ["read", "list"]
    description           = "test rule 2"
    required_parameters   = ["test_param2"]
    subscribe_event_types = ["test_events2", "test_events3"]

    allowed_parameter {
      key   = "all"
      value = []
    }

    denied_parameter {
      key   = "*"
      value = []
    }

    denied_parameter {
      key   = "foo"
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
  capabilities = ["create", "read", "update", "delete", "list", "patch"]
  required_parameters = ["test_param1"]
  subscribe_event_types = ["test_events1"]
  allowed_parameters = {
    "eggs" = ["foo", "bar"]
    "spam" = ["eggs"]
  }
  denied_parameters = {
    "a" = ["spam"]
    "b" = ["eggs"]
  }
  max_wrapping_ttl = "1h"
}

# test rule 2
path "secret/test2/*" {
  capabilities = ["read", "list"]
  required_parameters = ["test_param2"]
  subscribe_event_types = ["test_events2", "test_events3"]
  allowed_parameters = {
    "all" = []
  }
  denied_parameters = {
    "*" = []
    "foo" = []
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
