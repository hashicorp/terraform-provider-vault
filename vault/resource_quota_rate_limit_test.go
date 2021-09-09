package vault

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"
)

func randomQuotaRateString() string {
	whole := float64(acctest.RandIntRange(1000, 2000))
	decimal := float64(acctest.RandIntRange(0, 100)) / 100

	rateLimt := fmt.Sprintf("%.1f", whole+decimal)
	// Vault retuns floats with trailing zeros trimmed
	return strings.TrimRight(strings.TrimRight(rateLimt, "0"), ".")
}

func TestQuotaRateLimit(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-test")
	rateLimit := randomQuotaRateString()
	newRateLimit := randomQuotaRateString()
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testQuotaRateLimitCheckDestroy([]string{rateLimit, newRateLimit}),
		Steps: []resource.TestStep{
			{
				Config: testQuotaRateLimit_Config(name, "", rateLimit),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "name", name),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "path", ""),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "rate", rateLimit),
				),
			},
			{
				Config: testQuotaRateLimit_Config(name, "", newRateLimit),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "name", name),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "path", ""),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "rate", newRateLimit),
				),
			},
			{
				Config: testQuotaRateLimit_Config(name, "sys/", newRateLimit),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "name", name),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "path", "sys/"),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "rate", newRateLimit),
				),
			},
		},
	})
}

func testQuotaRateLimitCheckDestroy(rateLimits []string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testProvider.Meta().(*api.Client)

		for _, name := range rateLimits {
			resp, err := client.Logical().Read(quotaRateLimitPath(name))

			if err != nil {
				return err
			}

			if resp != nil {
				return fmt.Errorf("Resource Quota Rate Limit %s still exists", name)
			}
		}

		return nil
	}
}

// Caution: Don't set test rate values too low or other tests running concurrently might fail
func testQuotaRateLimit_Config(name, path, rate string) string {
	return fmt.Sprintf(`
resource "vault_quota_rate_limit" "foobar" {
  name = "%s"
  path = "%s"
  rate = %s
}
`, name, path, rate)
}
