package vault

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/go-version"
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

			rsPath = util.NormalizeMountPath(rsPath)
			for path, mount := range mounts {
				path = util.NormalizeMountPath(path)
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

// SkipIfAPIVersionLT skips of the running vault version is less-than ver.
func SkipIfAPIVersionLT(t *testing.T, m interface{}, ver *version.Version) {
	t.Helper()
	SkipOnAPIVersion(t, m, ver.LessThan, "Vault version lt %q", ver)
}

// SkipIfAPIVersionLTE skips if the running vault version is less-than-or-equal to ver.
func SkipIfAPIVersionLTE(t *testing.T, m interface{}, ver *version.Version) {
	t.Helper()
	SkipOnAPIVersion(t, m, ver.LessThanOrEqual, "Vault version lte %q", ver)
}

// SkipIfAPIVersionEQ skips if the running vault version is equal to ver.
func SkipIfAPIVersionEQ(t *testing.T, m interface{}, ver *version.Version) {
	t.Helper()
	SkipOnAPIVersion(t, m, ver.Equal, "Vault version eq %q", ver)
}

// SkipIfAPIVersionGT skips if the running vault version is greater-than ver.
func SkipIfAPIVersionGT(t *testing.T, m interface{}, ver *version.Version) {
	t.Helper()
	SkipOnAPIVersion(t, m, ver.GreaterThan, "Vault version gt %q", ver)
}

// SkipIfAPIVersionGTE skips if the running vault version is greater-than-or-equal to ver.
func SkipIfAPIVersionGTE(t *testing.T, m interface{}, ver *version.Version) {
	t.Helper()
	SkipOnAPIVersion(t, m, ver.GreaterThanOrEqual, "Vault version gte %q", ver)
}

func SkipOnAPIVersion(t *testing.T, m interface{}, cmp func(*version.Version) bool, format string, args ...interface{}) {
	t.Helper()

	p := m.(*provider.ProviderMeta)
	curVer := p.GetVaultVersion()
	if curVer == nil {
		t.Fatalf("vault version not set on %T", p)
	}
	if !cmp(curVer) {
		t.Skipf(format, args...)
	}
}
