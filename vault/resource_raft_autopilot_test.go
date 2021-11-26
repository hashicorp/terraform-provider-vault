package vault

import (
	"os"
	"strconv"
	"testing"

	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

func TestAccRaftAutopilotConfig_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck: func() {
			util.TestAccPreCheck(t)
			if _, ok := os.LookupEnv("SKIP_RAFT_TESTS"); ok {
				t.Skip("Warning: SKIP_RAFT_TESTS set, skipping test")
			}
		},
		CheckDestroy: testAccRaftAutopilotConfigCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccRaftAutopilotConfig_basic(true, "12h0m0s", 3),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_raft_autopilot.test", "cleanup_dead_servers", "true"),
					resource.TestCheckResourceAttr("vault_raft_autopilot.test", "dead_server_last_contact_threshold", "12h0m0s"),
					resource.TestCheckResourceAttr("vault_raft_autopilot.test", "last_contact_threshold", autopilotDefaults["last_contact_threshold"].(string)),
					resource.TestCheckResourceAttr("vault_raft_autopilot.test", "max_trailing_logs", strconv.Itoa(autopilotDefaults["max_trailing_logs"].(int))),
					resource.TestCheckResourceAttr("vault_raft_autopilot.test", "min_quorum", "3"),
					resource.TestCheckResourceAttr("vault_raft_autopilot.test", "server_stabilization_time", autopilotDefaults["server_stabilization_time"].(string)),
				),
			},
			{
				Config: testAccRaftAutopilotConfig_updated(true, "30s", "20s", 100, 5, "50s"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_raft_autopilot.test", "cleanup_dead_servers", "true"),
					resource.TestCheckResourceAttr("vault_raft_autopilot.test", "dead_server_last_contact_threshold", "30s"),
					resource.TestCheckResourceAttr("vault_raft_autopilot.test", "last_contact_threshold", "20s"),
					resource.TestCheckResourceAttr("vault_raft_autopilot.test", "max_trailing_logs", "100"),
					resource.TestCheckResourceAttr("vault_raft_autopilot.test", "min_quorum", "5"),
					resource.TestCheckResourceAttr("vault_raft_autopilot.test", "server_stabilization_time", "50s"),
				),
			},
		},
	})
}

func testAccRaftAutopilotConfigCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_raft_autopilot_config" {
			continue
		}
		autopilot, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return err
		}
		for k, v := range autopilotDefaults {
			if autopilot.Data[k] != v {
				return fmt.Errorf("autopilot config: %s not reverted to default", k)
			}
		}
	}
	return nil
}

func testAccRaftAutopilotConfig_basic(cleanup bool, dsThresh string, quorum int) string {
	return fmt.Sprintf(`
resource "vault_raft_autopilot" "test" {
  cleanup_dead_servers = %t
  dead_server_last_contact_threshold = "%s"
  min_quorum = %d
}`, cleanup, dsThresh, quorum)
}

func testAccRaftAutopilotConfig_updated(cleanup bool, dsThresh string, lcThresh string, logs int, quorum int, stabTime string) string {
	return fmt.Sprintf(`
resource "vault_raft_autopilot" "test" {
  cleanup_dead_servers = %t
  dead_server_last_contact_threshold = "%s"
  last_contact_threshold = "%s"
  max_trailing_logs = %d
  min_quorum = %d
  server_stabilization_time = "%s"
}`, cleanup, dsThresh, lcThresh, logs, quorum, stabTime)
}
