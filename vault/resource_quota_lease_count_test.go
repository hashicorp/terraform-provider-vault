package vault

import (
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
)

func randomQuotaLeaseString() string {
	whole := acctest.RandIntRange(1000, 2000)
	return strconv.Itoa(whole + 1000)
}

func TestQuotaLeaseCount(t *testing.T) {
	isEnterprise := os.Getenv("TF_ACC_ENTERPRISE")
	if isEnterprise == "" {
		t.Skip("TF_ACC_ENTERPRISE is not set, test is applicable only for Enterprise version of Vault")
	}
	name := acctest.RandomWithPrefix("tf-test")
	leaseCount := randomQuotaLeaseString()
	newLeaseCount := randomQuotaLeaseString()
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testQuotaLeaseCountCheckDestroy([]string{leaseCount, newLeaseCount}),
		Steps: []resource.TestStep{
			{
				Config: testQuotaLeaseCount_Config(name, "", leaseCount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_quota_lease_count.foobar", "name", name),
					resource.TestCheckResourceAttr("vault_quota_lease_count.foobar", "path", ""),
					resource.TestCheckResourceAttr("vault_quota_lease_count.foobar", "max_leases", leaseCount),
				),
			},
			{
				Config: testQuotaLeaseCount_Config(name, "", newLeaseCount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_quota_lease_count.foobar", "name", name),
					resource.TestCheckResourceAttr("vault_quota_lease_count.foobar", "path", ""),
					resource.TestCheckResourceAttr("vault_quota_lease_count.foobar", "max_leases", newLeaseCount),
				),
			},
			{
				Config: testQuotaLeaseCount_Config(name, "sys/", newLeaseCount),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_quota_lease_count.foobar", "name", name),
					resource.TestCheckResourceAttr("vault_quota_lease_count.foobar", "path", "sys/"),
					resource.TestCheckResourceAttr("vault_quota_lease_count.foobar", "max_leases", newLeaseCount),
				),
			},
		},
	})
}

func testQuotaLeaseCountCheckDestroy(leaseCounts []string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testProvider.Meta().(*api.Client)

		for _, name := range leaseCounts {
			resp, err := client.Logical().Read(quotaLeaseCountPath(name))

			if err != nil {
				return err
			}

			if resp != nil {
				return fmt.Errorf("Resource Quota Lease Count %s still exists", name)
			}
		}

		return nil
	}
}

// Caution: Don't set test max_leases values too low or other tests running concurrently might fail
func testQuotaLeaseCount_Config(name, path, max_leases string) string {
	return fmt.Sprintf(`
resource "vault_quota_lease_count" "foobar" {
  name = "%s"
  path = "%s"
  max_leases = %s
}
`, name, path, max_leases)
}
