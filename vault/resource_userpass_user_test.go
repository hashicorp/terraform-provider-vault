// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccUserpassUser_basic(t *testing.T) {
	mount := acctest.RandomWithPrefix("userpass")
	username := "u-se_r1"
	password := "pa33w$rd"
	resourceType := "vault_userpass_user"
	resourceName := resourceType + ".user"
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testutil.TestAccPreCheck(t) },
		CheckDestroy: testCheckMountDestroyed(resourceType, consts.MountTypeUserpass, consts.FieldUsername),
		Steps: []resource.TestStep{
			{
				Config: testAccUserpassUserConfig_basic(mount, username, password, []string{"admin", "security"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "id", "auth/"+mount+"/users/"+username),
					resource.TestCheckResourceAttr(resourceName, "mount", mount),
					resource.TestCheckResourceAttr(resourceName, "username", username),
					resource.TestCheckResourceAttr(resourceName, "password", password),
					resource.TestCheckResourceAttr(resourceName, "token_policies.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "token_policies.0", "admin"),
					resource.TestCheckResourceAttr(resourceName, "token_policies.1", "security"),
				),
			},
			{
				Config: testAccUserpassUserConfig_basic(mount, username, password, []string{"updated_policy"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "id", "auth/"+mount+"/users/"+username),
					resource.TestCheckResourceAttr(resourceName, "mount", mount),
					resource.TestCheckResourceAttr(resourceName, "username", username),
					resource.TestCheckResourceAttr(resourceName, "password", password),
					resource.TestCheckResourceAttr(resourceName, "token_policies.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "token_policies.0", "updated_policy"),
				),
			},
			testutil.GetImportTestStep(resourceName, false, nil, consts.FieldPassword),
		},
	})
}

func TestAccUserpassHelpers(t *testing.T) {
	testCases := []struct {
		mount    string
		username string
		path     string
	}{
		{
			mount:    "userpass",
			username: "username",
			path:     "auth/userpass/users/username",
		},
		{
			mount:    "userpa/ss",
			username: "username",
			path:     "auth/userpa/ss/users/username",
		},
		{
			mount:    "userpass",
			username: "us/ername",
			path:     "auth/userpass/users/us/ername",
		},
		{
			mount:    "userpa/ss",
			username: "us/ername",
			path:     "auth/userpa/ss/users/us/ername",
		},
		{
			mount:    "!userp@/s@$ss",
			username: "b-l@m_hemu",
			path:     "auth/!userp@/s@$ss/users/b-l@m_hemu",
		},
	}
	for _, tc := range testCases {
		actualPath := userPath(tc.mount, tc.username)
		if actualPath != tc.path {
			t.Fatalf("expected path '%s', got: '%s'", tc.path, actualPath)
		}

		actualmount, err := mountFromPath(tc.path)
		if err != nil || actualmount != tc.mount {
			t.Fatalf("err: %s expected mount: '%s' actual mount: '%s'", err, tc.mount, actualmount)
		}

		actualUsername, err := usernameFromPath(tc.path)
		if err != nil || actualUsername != tc.username {
			t.Fatalf("err: %s expected username: '%s' actual username: '%s'", err, tc.username, actualUsername)
		}
	}
}

func testAccUserpassUserConfig_basic(mount string, username string, password string, policies []string) string {
	p, _ := json.Marshal(policies)
	return fmt.Sprintf(`
resource "vault_auth_backend" "userpass" {
	type = "userpass"
	path = "%s"
}

resource "vault_userpass_user" "user" {
	mount = vault_auth_backend.userpass.path
	username = "%s"
	password = "%s"
	token_policies = %s
}
`, mount, username, password, p)
}
