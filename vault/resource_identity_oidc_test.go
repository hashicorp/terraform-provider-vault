// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccIdentityOidc(t *testing.T) {
	issuer := "https://www.acme.com"
	issuerNew := "https://www.acme-two.com"

	const resourceName = "vault_identity_oidc.server"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t),
		CheckDestroy:             testAccCheckIdentityOidcDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccIdentityOidcConfig(issuer),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "issuer", issuer),
					testAccIdentityOidcCheckAttrs(resourceName),
				),
			},
			{
				Config: testAccIdentityOidcConfig(issuerNew),
				Check: resource.ComposeTestCheckFunc(
					testAccIdentityOidcCheckAttrs(resourceName),
					resource.TestCheckResourceAttr(resourceName, "issuer", issuerNew),
				),
			},
		},
	})
}

func testAccCheckIdentityOidcDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*provider.ProviderMeta).MustGetClient()
	path := identityOidcPathTemplate

	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading IdentityOidc: %s", err)
	}
	if resp == nil {
		return fmt.Errorf("error reading IdentityOidc: %s", err)
	}

	if resp.Data["issuer"] != "" {
		return fmt.Errorf("expected OIDC issuer to be reset to empty but got %q", resp.Data["issuer"])
	}

	return nil
}

func testAccIdentityOidcCheckAttrs(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, err := testutil.GetResourceFromRootModule(s, resourceName)
		if err != nil {
			return err
		}

		client, err := provider.GetClient(rs.Primary, testProvider.Meta())
		if err != nil {
			return err
		}

		path := identityOidcPathTemplate

		attrs := map[string]string{
			"issuer": "issuer",
		}

		tAttrs := []*testutil.VaultStateTest{}
		for k, v := range attrs {
			ta := &testutil.VaultStateTest{
				ResourceName: resourceName,
				StateAttr:    k,
				VaultAttr:    v,
			}

			tAttrs = append(tAttrs, ta)
		}

		return testutil.AssertVaultState(client, s, path, tAttrs...)
	}
}

func testAccIdentityOidcConfig(issuer string) string {
	return fmt.Sprintf(`
resource "vault_identity_oidc" "server" {
	issuer = "%s"
}
`, issuer)
}
