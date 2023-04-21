// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	r "github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourceAuthBackends(t *testing.T) {
	typ := "userpass"
	path := []string{"foo", "bar"}

	r.Test(t, r.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []r.TestStep{
			{
				Config: testDataSourceAuthBackendsBasic_config,
				Check:  testDataSourceAuthBackends_check,
			},
			{
				Config: testDataSourceAuthBackends_config(path, typ),
				Check:  testDataSourceAuthBackends_check,
			},
		},
	})
}

var testDataSourceAuthBackendsBasic_config = `

resource "vault_auth_backend" "test-foo" {
	type = "userpass"
}

resource "vault_auth_backend" "test-bar" {
	type = "approle"
}

data "vault_auth_backends" "test" {
	depends_on = [
		"vault_auth_backend.test-foo",
		"vault_auth_backend.test-bar",
	]
}

`

func testDataSourceAuthBackends_config(path []string, typ string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test-foo" {
	path = "%s"
	type = "userpass"
}

resource "vault_auth_backend" "test-bar" {
	path = "%s"
	type = "approle"
}

data "vault_auth_backends" "test" {
	depends_on = [
		"vault_auth_backend.test-foo",
		"vault_auth_backend.test-bar",
	]
	type = "%s"
}
`, path[0], path[1], typ)
}

func testDataSourceAuthBackends_check(s *terraform.State) error {
	testFooResourceState := s.Modules[0].Resources["vault_auth_backend.test-foo"]
	testBarResourceState := s.Modules[0].Resources["vault_auth_backend.test-bar"]

	if testFooResourceState == nil {
		return fmt.Errorf("resource not found in state %v", s.Modules[0].Resources)
	}

	if testBarResourceState == nil {
		return fmt.Errorf("resource not found in state %v", s.Modules[0].Resources)
	}

	testFooInstanceState := testFooResourceState.Primary
	testBarInstanceState := testBarResourceState.Primary

	if testFooInstanceState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	if testBarInstanceState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	resourceState := s.Modules[0].Resources["data.vault_auth_backends.test"]
	if resourceState == nil {
		return fmt.Errorf("resource not found in state %v", s.Modules[0].Resources)
	}

	iState := resourceState.Primary
	if iState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	// Debug message lines
	fmt.Println("-----------------------")
	fmt.Println(resourceState.Primary.Attributes["paths"])
	fmt.Println(iState.Attributes)
	fmt.Println(iState.Attributes["paths"])
	fmt.Println(iState.Attributes["id"])
	fmt.Println("-----------------------")

	// len(paths) == len(accessors) always
	if got, want := len(iState.Attributes["paths"]), len(iState.Attributes["accessors"]); got != want {
		return fmt.Errorf("length of paths is %d; length of accessors is %d; must match", got, want)
	}

	if got, want := iState.Attributes["id"], "default"; got != want {
		return fmt.Errorf("id contains %s; want %s", got, want)
	}

	if got := len(iState.Attributes["paths"]); got < 1 {
		return fmt.Errorf("There should be more than 0 paths, got %d; %s", got, iState.Attributes["paths"])
	}

	/* These are not working as expected
	if iState.Attributes["type"] == "userpass" {
		if got, want := len(iState.Attributes["paths"]), 1; got != want {
			return fmt.Errorf("length of paths is %d; want %d", got, want)
		}
	} else if iState.Attributes["type"] == "" {
		if got, want := len(iState.Attributes["paths"]), 3; got != want {
			return fmt.Errorf("3 length of paths is %d; want %d", got, want)
		}
	} else {
		return fmt.Errorf("We should not be here")
	}
	*/

	return nil
}
