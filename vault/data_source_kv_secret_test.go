// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourceKVSecret(t *testing.T) {
	var p *schema.Provider
	t.Parallel()
	mount := acctest.RandomWithPrefix("tf-kv")
	name := acctest.RandomWithPrefix("foo")

	expectedSubkeys := `{"baz":{"riff":"raff"},"foo":"bar","zip":"zap","test":false}`

	resourceName := "data.vault_kv_secret.test"
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories(context.Background(), t, &p),
		PreCheck:                 func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceKVSecretConfig(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/%s", mount, name)),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLeaseRenewable, "false"),
					resource.TestCheckResourceAttr(resourceName, "data.%", "4"),
					resource.TestCheckResourceAttr(resourceName, "data.zip", "zap"),
					resource.TestCheckResourceAttr(resourceName, "data.foo", "bar"),
					resource.TestCheckResourceAttr(resourceName, "data.test", "false"),
					resource.TestCheckResourceAttr(resourceName, "data.baz", "{\"riff\":\"raff\"}"),
					testutil.CheckJSONData(resourceName, consts.FieldDataJSON, expectedSubkeys),
				),
			},
			{
				Config: testDataSourceKVSecretConfig(mount, fmt.Sprintf("%s-updated", name)),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/%s-updated", mount, name)),
					resource.TestCheckResourceAttr(resourceName, consts.FieldLeaseRenewable, "false"),
					resource.TestCheckResourceAttr(resourceName, "data.%", "4"),
					resource.TestCheckResourceAttr(resourceName, "data.zip", "zap"),
					resource.TestCheckResourceAttr(resourceName, "data.foo", "bar"),
					resource.TestCheckResourceAttr(resourceName, "data.test", "false"),
					resource.TestCheckResourceAttr(resourceName, "data.baz", "{\"riff\":\"raff\"}"),
					testutil.CheckJSONData(resourceName, consts.FieldDataJSON, expectedSubkeys),
				),
			},
		},
	})
}

func testDataSourceKVSecretConfig(mount, name string) string {
	return fmt.Sprintf(`
%s

resource "vault_kv_secret" "test" {
  path = "${vault_mount.kvv1.path}/%s"
  data_json = jsonencode(
    {
      zip  = "zap",
      foo  = "bar",
      test = false
      baz = {
          riff = "raff"
        }
    }
  )
}

data "vault_kv_secret" "test" {
  path = vault_kv_secret.test.path
}`, kvV1MountConfig(mount), name)
}
