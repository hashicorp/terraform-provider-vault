package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
)

func TestQuotaRateLimit(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-test")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { testAccPreCheck(t) },
		CheckDestroy: testQuotaRateLimitCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testQuotaRateLimit_Config(name, "", "1000.0"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "name", name),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "path", ""),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "rate", "1000"),
				),
			},
			{
				Config: testQuotaRateLimit_Config(name, "", "1234.5"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "name", name),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "path", ""),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "rate", "1234.5"),
				),
			},
			{
				Config: testQuotaRateLimit_Config(name, "sys/", "1234.5"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "name", name),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "path", "sys/"),
					resource.TestCheckResourceAttr("vault_quota_rate_limit.foobar", "rate", "1234.5"),
				),
			},
		},
	})
}

func testQuotaRateLimitCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_quota_rate_limit" {
			continue
		}
		name := rs.Primary.Attributes["name"]
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
