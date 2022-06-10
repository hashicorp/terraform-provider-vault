package vault

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

func testCheckMountDestroyed(resourceType, mountType, pathField string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if pathField == "" {
			pathField = consts.FieldPath
		}
		for _, rs := range s.RootModule().Resources {
			if rs.Type != resourceType {
				continue
			}

			client, e := provider.GetClient(rs.Primary, testProvider.Meta())
			if e != nil {
				return e
			}

			mounts, err := client.Sys().ListMounts()
			if err != nil {
				return err
			}

			rsPath, ok := rs.Primary.Attributes[pathField]
			if !ok {
				return fmt.Errorf("resource's InstanceState missing required field %q", pathField)
			}

			rsPath = util.NormalizeMountPath(rsPath)
			for path, mount := range mounts {
				path = util.NormalizeMountPath(path)
				if mount.Type == mountType && path == rsPath {
					return fmt.Errorf("mount %q still exists", path)
				}
			}
		}

		return nil
	}
}
