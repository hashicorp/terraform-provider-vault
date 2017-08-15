package vault

import (
	"testing"

	"fmt"

	"encoding/json"

	r "github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
)

func TestResourceToken(t *testing.T) {
	r.Test(t, r.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []r.TestStep{
			// This first step just sets a policy that will be used later
			r.TestStep{
				Config: preConfig,
			},
			r.TestStep{
				Config: test1Config,
				Check:  test1Check,
			},
			r.TestStep{
				Config: test2Config,
				Check:  test2Check,
			},
		},
	})
}

var preConfig = `
resource "vault_policy" "test" {
	name = "test-policy"
	policy = <<EOT
path "secret/*" {
	policy = "read"
}
EOT
}
`

var test1Config = `
resource "vault_token" "test_token" {
	display_name = "test token"
	policies = ["test-policy"]
	period = "240h"
	wrap = false
}
`

func test1Check(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["vault_token.test_token"]
	if resourceState == nil {
		return fmt.Errorf("vault token resource not found")
	}

	instanceState := resourceState.Primary
	if instanceState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	if instanceState.ID != instanceState.Attributes["accessor"] {
		return fmt.Errorf("id doesn't match accessor token")
	}

	if instanceState.Attributes["display_name"] != "test token" {
		return fmt.Errorf("unexpected display name")
	}

	//if got, want := instanceState.Attributes["token"], "test_token_id"; got != want {
	//	return fmt.Errorf("unexpected token ID, got: %v wanted: %v", got, want)
	//}

	client := testProvider.Meta().(*api.Client)
	token, err := client.Auth().Token().Lookup(instanceState.Attributes["token"])
	if err != nil {
		return fmt.Errorf("error reading back token: %s", err)
	}

	if got, want := len(token.Data["policies"].([]interface{})), 2; got != want {
		return fmt.Errorf("unexpected number of policies found got: %v, wanted: %v", got, want)
	}

	if got, want := token.Data["policies"].([]interface{})[1].(string), "test-policy"; got != want {
		return fmt.Errorf("expected policy not found")
	}

	if got, want := token.Data["period"].(json.Number).String(), "864000"; got != want {
		return fmt.Errorf("expected period to match configuration")
	}

	if got, want := token.Data["orphan"].(bool), true; got != want {
		return fmt.Errorf("expected token to be an orphan")
	}

	if token.WrapInfo != nil {
		return fmt.Errorf("token should not be wrapped")
	}

	return nil
}

var test2Config = `
resource "vault_token" "test2-token" {
	wrap = true
	no_default_policy = true
	policies = ["test-policy"]
	renewable = false
	orphan = false
		meta {
		testkey = "testdata"
	}
}
`

func test2Check(s *terraform.State) error {
	resourceState := s.Modules[0].Resources["vault_token.test2-token"]
	if resourceState == nil {
		return fmt.Errorf("vault token resource not found")
	}

	instanceState := resourceState.Primary
	if instanceState.ID != instanceState.Attributes["accessor"] {
		return fmt.Errorf("id doesn't match accessor token")
	}

	if instanceState.Attributes["display_name"] != "" {
		return fmt.Errorf("unexpected display name")
	}

	client := testProvider.Meta().(*api.Client)
	wToken, err := client.Auth().Token().Lookup(instanceState.Attributes["token"])
	if err != nil {
		return fmt.Errorf("error reading token: %v", err)
	}

	if got, want := wToken.Data["num_uses"].(json.Number).String(), "1"; got != want {
		fmt.Errorf("wrapped token has wrong num of uses, got: %v wanted %v", got, want)
	}

	token, err := client.Auth().Token().LookupAccessor(instanceState.ID)
	if err != nil {
		return fmt.Errorf("error reading token: %v", err)
	}

	if got, want := len(token.Data["policies"].([]interface{})), 1; got != want {
		return fmt.Errorf("wrong number of policies found, got: %v wanted: %v", got, want)
	}

	if got, want := token.Data["renewable"].(bool), false; got != want {
		return fmt.Errorf("token should not be renewable")
	}

	if got, want := token.Data["orphan"].(bool), false; got != want {
		return fmt.Errorf("token should not be an orphan")
	}

	if got, want := token.Data["explicit_max_ttl"].(json.Number).String(), "2764800"; got != want {
		return fmt.Errorf("token explicit max ttl does not match expected")
	}

	if got, want := token.Data["meta"].(map[string]interface{})["testkey"].(string), "testdata"; got != want {
		return fmt.Errorf("metadata does not match expected: got: %v wanted: %v", got, want)
	}

	return nil
}
