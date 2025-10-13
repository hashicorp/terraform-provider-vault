// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"regexp"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/terraform-provider-vault/util/mountutil"
)

func testCheckMountDestroyed(resourceType, mountType, pathField string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if pathField == "" {
			pathField = consts.FieldPath
		}

		var resourceCount int
		for _, rs := range s.RootModule().Resources {
			if rs.Type != resourceType {
				continue
			}

			resourceCount++

			client, e := provider.GetClient(rs.Primary, testProvider.Meta())
			if e != nil {
				return e
			}

			rsPath, ok := rs.Primary.Attributes[pathField]
			if !ok {
				return fmt.Errorf("resource's InstanceState missing required field %q", pathField)
			}

			mounts, err := client.Sys().ListMounts()
			if err != nil {
				if ns := client.Namespace(); ns != "" {
					// handle the case where the test creates the namespace,
					// in which case the mount will have been destroyed along with
					// its namespace.
					if util.Is404(err) {
						if match := regexp.MustCompile(fmt.Sprintf(
							`no handler for route "%s/sys/mounts". route entry not found.`, ns),
						).MatchString(err.Error()); match {
							return nil
						}
					}
				}

				return err
			}

			rsPath = mountutil.NormalizeMountPath(rsPath)
			for path, mount := range mounts {
				path = mountutil.NormalizeMountPath(path)
				if mount.Type == mountType && path == rsPath {
					return fmt.Errorf("mount %q still exists", path)
				}
			}
		}

		if resourceCount == 0 {
			return fmt.Errorf("expected at least 1 resources of type %q in State", resourceType)
		}

		return nil
	}
}
