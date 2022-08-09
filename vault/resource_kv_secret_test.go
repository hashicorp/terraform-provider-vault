package vault

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccKVSecret(t *testing.T) {
	resourceName := "vault_kv_secret.test"
	mount := acctest.RandomWithPrefix("tf-kvv2")
	name := acctest.RandomWithPrefix("tf-secret")

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testKVSecretConfig_basic(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/%s", mount, name)),
					resource.TestCheckResourceAttr(resourceName, "data.zip", "zap"),
					resource.TestCheckResourceAttr(resourceName, "data.foo", "bar"),
					testResourceKVSecret_basic_apiAcessCheck,
				),
			},
			{
				Config: testKVSecretConfig_updated(mount, name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, consts.FieldPath, fmt.Sprintf("%s/%s", mount, name)),
					resource.TestCheckResourceAttr(resourceName, "data.zip", "zoop"),
					resource.TestCheckResourceAttr(resourceName, "data.foo", "bar"),
					testResourceKVSecret_updated_apiAcessCheck,
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{consts.FieldDataJSON},
			},
		},
	})
}

func kvV1MountConfig(path string) string {
	ret := fmt.Sprintf(`
resource "vault_mount" "kvv1" {
	path        = "%s"
	type        = "kv"
    options     = { version = "1" }
    description = "KV Version 1 secret engine mount"
}`, path)

	return ret
}

func testKVSecretConfig_basic(mount, name string) string {
	ret := fmt.Sprintf(`
%s

`, kvV1MountConfig(mount))

	ret += fmt.Sprintf(`
resource "vault_kv_secret" "test" {
  path = "${vault_mount.kvv1.path}/%s"
  data_json = jsonencode(
    {
      zip = "zap",
      foo = "bar"
    }
  )
}`, name)

	return ret
}

func testKVSecretConfig_updated(mount, name string) string {
	ret := fmt.Sprintf(`
%s

`, kvV1MountConfig(mount))

	ret += fmt.Sprintf(`
resource "vault_kv_secret" "test" {
  path = "${vault_mount.kvv1.path}/%s"
  data_json = jsonencode(
    {
      zip = "zoop",
      foo = "bar"
    }
  )
}`, name)

	return ret
}

func testResourceKVSecret_apiAcessCheck(s *terraform.State, want string) error {
	resourceState := s.Modules[0].Resources["vault_kv_secret.test"]
	state := resourceState.Primary

	path := state.ID

	client, err := provider.GetClient(state, testProvider.Meta())
	if err != nil {
		return err
	}

	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading back secret: %s", err)
	}

	if got := secret.Data["zip"]; got != want {
		return fmt.Errorf("'zip' data is %q; want %q", got, want)
	}

	return nil

}

func testResourceKVSecret_basic_apiAcessCheck(s *terraform.State) error {
	return testResourceKVSecret_apiAcessCheck(s, "zap")
}

func testResourceKVSecret_updated_apiAcessCheck(s *terraform.State) error {
	return testResourceKVSecret_apiAcessCheck(s, "zoop")
}
