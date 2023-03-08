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
	typ := []string{"userpass", "userpass", "approle", "approle"}
	path := []string{"foo", "bar", "baz", "boo"}
	r.Test(t, r.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []r.TestStep{
			{
				Config: testDataSourceAuthBackendsBasic_config,
				Check:  testDataSourceAuthBackends_check,
			},
			{
				Config: testDataSourceAuthBackends_config(typ, path),
				Check:  testDataSourceAuthBackends_check,
			},
		},
	})
}

var testDataSourceAuthBackendsBasic_config = `

resource "vault_auth_backend" "test1" {
	type = "userpass"
	path = "test-up"
}

resource "vault_auth_backend" "test2" {
	type = "userpass"
	path = "test-up2"
}

resource "vault_auth_backend" "test3" {
	type = "approle"
	path = "test-ar"
}

resource "vault_auth_backend" "test4" {
	type = "approle"
	path = "test-ar2"
}

data "vault_auth_backends" "test" { }

`

/* Some work to be done here */
func testDataSourceAuthBackends_config(typ []string, path []string) string {
	return fmt.Sprintf(`
resource "vault_auth_backend" "test1" {
	path = "%s"
	type = "%s"
}

resource "vault_auth_backend" "test2" {
	path = "%s"
	type = "%s"
}

resource "vault_auth_backend" "test3" {
	path = "%s"
	type = "%s"
}

resource "vault_auth_backend" "test4" {
	path = "%s"
	type = "%s"
}

data "vault_auth_backends" "test" {
	path = vault_auth_backend.test.path
}
`, typ[0], path[0], typ[1], path[1], typ[2], path[2], typ[3], path[3])
}

func testDataSourceAuthBackends_check(s *terraform.State) error {
	test1ResourceState := s.Modules[0].Resources["vault_auth_backend.test1"]
	test2ResourceState := s.Modules[0].Resources["vault_auth_backend.test2"]
	test3ResourceState := s.Modules[0].Resources["vault_auth_backend.test3"]
	test4ResourceState := s.Modules[0].Resources["vault_auth_backend.test4"]

	if test1ResourceState == nil {
		return fmt.Errorf("resource not found in state %v", s.Modules[0].Resources)
	}

	if test2ResourceState == nil {
		return fmt.Errorf("resource not found in state %v", s.Modules[0].Resources)
	}

	if test3ResourceState == nil {
		return fmt.Errorf("resource not found in state %v", s.Modules[0].Resources)
	}

	if test4ResourceState == nil {
		return fmt.Errorf("resource not found in state %v", s.Modules[0].Resources)
	}

	test1InstanceState := test1ResourceState.Primary
	test2InstanceState := test2ResourceState.Primary
	test3InstanceState := test3ResourceState.Primary
	test4InstanceState := test4ResourceState.Primary

	if test1InstanceState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	if test2InstanceState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	if test3InstanceState == nil {
		return fmt.Errorf("resource has no primary instance")
	}

	if test4InstanceState == nil {
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

	if got, want := len(iState.Attributes["paths"]), len(iState.Attributes["accessors"]); got != want {
		return fmt.Errorf("length of paths is %d; length of accessors is %d; must match", got, want)
	}

	if iState.Attributes["type"] == "" {
		if got, want := len(iState.Attributes["paths"]), 4; got != want {
			return fmt.Errorf("length of paths is %d; want %d", got, want)
		}
	} else {
		if got, want := len(iState.Attributes["paths"]), 2; got != want {
			return fmt.Errorf("length of paths is %d; want %d", got, want)
		}
	}

	return nil
}
