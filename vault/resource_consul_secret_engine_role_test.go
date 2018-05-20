package vault

import (
	"encoding/base64"
	"fmt"
	"testing"

	r "github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
)

func TestResourceConsulSecretRole(t *testing.T) {
	client := testProvider.Meta().(*api.Client)
	_, err := client.Logical().Delete("/sys/mounts/consul")
	if err != nil {
		t.Skip("could not unmount consul secret engine", err)
	}

	data := map[string]interface{}{}
	data["type"] = "consul"
	_, err2 := client.Logical().Write("/sys/mounts/consul", data)
	if err2 != nil {
		t.Skip("could not mount consul secret engine", err)
	}

	r.Test(t, r.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testAccPreCheck(t) },
		Steps: []r.TestStep{
			r.TestStep{
				Config: testResourceConsulSecretRole_config,
				Check:  testResourceConsulSecretRole_check,
			},
		},
	})
}

var testResourceConsulSecretRole_config = `

resource "vault_consul_secret_engine_role" "test" {
  mount = "consul"
  name = "test"
  role = <<EOF
key "foo" { policy = "read" }
key "bar/baz" { policy = "write" }
EOF
}

`

func testResourceConsulSecretRole_check(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)
	resourceState := s.Modules[0].Resources["vault_consul_secret_engine_role.test"]

	if resourceState == nil {
		return fmt.Errorf("resource not found in state %v", s.Modules[0].Resources)
	}

	iState := resourceState.Primary
	if iState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	mountName := resourceState.Primary.Attributes["mount"]
	if mountName != "consul" {
		return fmt.Errorf("resource mount name should be 'consul', but was %s", mountName)
	}

	role, err := client.Logical().Read("/consul/roles/test")
	if err != nil {
		return fmt.Errorf("error reading role from path /consul/roles/test; got %s", err)
	}

	expectedEncodedPolicy := "a2V5ICJmb28iIHsgcG9saWN5ID0gInJlYWQiIH0Ka2V5ICJiYXIvYmF6IiB7IHBvbGljeSA9ICJ3cml0ZSIgfQo="
	encodedPolicy := role.Data["policy"]
	if encodedPolicy != expectedEncodedPolicy {
		return fmt.Errorf("encoded policy should be %s but was %s", expectedEncodedPolicy, encodedPolicy)
	}

	expectedTokenType := "client"
	tokenType := role.Data["token_type"]
	if tokenType != expectedTokenType {
		return fmt.Errorf("token type should be %s but was %s", expectedTokenType, tokenType)
	}

	roleBase64Encoded := base64.StdEncoding.EncodeToString([]byte(resourceState.Primary.Attributes["role"]))
	if roleBase64Encoded != encodedPolicy {
		return fmt.Errorf("encoded policy %s from backend does not match the test policy %s", encodedPolicy, roleBase64Encoded)
	}

	return nil
}
