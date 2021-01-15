package vault

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
)

func randomQuotaLeaseString() string {
	whole := float64(acctest.RandIntRange(1000, 2000))
	decimal := float64(acctest.RandIntRange(0, 100)) / 100

	rateLimt := fmt.Sprintf("%.1f", whole+decimal)
	// Vault retuns floats with trailing zeros trimmed
	return strings.TrimRight(strings.TrimRight(rateLimt, "0"), ".")
}

func TestQuotaLeaseCount(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-test")
	rateLimit := randomQuotaLeaseString()
	newRateLimit := randomQuotaLeaseString()
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testQuotaLeaseCountCheckDestroy([]string{rateLimit, newRateLimit}),
		Steps: []resource.TestStep{
			{
				Config: testQuotaLeaseCount_Config(name, "", rateLimit),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_quota_lease_count.foobar", "name", name),
					resource.TestCheckResourceAttr("vault_quota_lease_count.foobar", "path", ""),
					resource.TestCheckResourceAttr("vault_quota_lease_count.foobar", "max_leases", rateLimit),
				),
			},
			{
				Config: testQuotaLeaseCount_Config(name, "", newRateLimit),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_quota_lease_count.foobar", "name", name),
					resource.TestCheckResourceAttr("vault_quota_lease_count.foobar", "path", ""),
					resource.TestCheckResourceAttr("vault_quota_lease_count.foobar", "max_leases", newRateLimit),
				),
			},
			{
				Config: testQuotaLeaseCount_Config(name, "sys/", newRateLimit),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_quota_lease_count.foobar", "name", name),
					resource.TestCheckResourceAttr("vault_quota_lease_count.foobar", "path", "sys/"),
					resource.TestCheckResourceAttr("vault_quota_lease_count.foobar", "max_leases", newRateLimit),
				),
			},
		},
	})
}

func testQuotaLeaseCountCheckDestroy(rateLimits []string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testProvider.Meta().(*api.Client)

		for _, name := range rateLimits {
			resp, err := client.Logical().Read(QuotaLeaseCountPath(name))

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
func testQuotaLeaseCount_Config(name, path, rate string) string {
	return fmt.Sprintf(`
resource "vault_quota_lease_count" "foobar" {
  name = "%s"
  path = "%s"
  max_leases = %s
}
`, name, path, max_leases)
}
