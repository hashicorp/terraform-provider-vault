package vault

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccRaftAutopilotConfig_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck: func() {
			testutil.TestAccPreCheck(t)
			testutil.SkipTestEnvSet(t, "SKIP_RAFT_TESTS")
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
					resource.TestCheckResourceAttr("vault_raft_autopilot.test", "min_quorum", strconv.Itoa(autopilotDefaults["min_quorum"].(int))),
					resource.TestCheckResourceAttr("vault_raft_autopilot.test", "server_stabilization_time", autopilotDefaults["server_stabilization_time"].(string)),
					resource.TestCheckResourceAttr("vault_raft_autopilot.test", "disable_upgrade_migration", "false"),
				),
			},
			{
				Config: testAccRaftAutopilotConfig_updated(true, true, "30s", "20s", "50s", 100, 5),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_raft_autopilot.test", "cleanup_dead_servers", "true"),
					resource.TestCheckResourceAttr("vault_raft_autopilot.test", "dead_server_last_contact_threshold", "30s"),
					resource.TestCheckResourceAttr("vault_raft_autopilot.test", "last_contact_threshold", "20s"),
					resource.TestCheckResourceAttr("vault_raft_autopilot.test", "max_trailing_logs", "100"),
					resource.TestCheckResourceAttr("vault_raft_autopilot.test", "min_quorum", "5"),
					resource.TestCheckResourceAttr("vault_raft_autopilot.test", "server_stabilization_time", "50s"),
					resource.TestCheckResourceAttr("vault_raft_autopilot.test", "disable_upgrade_migration", "true"),
				),
			},
		},
	})
}

func testAccRaftAutopilotConfigCheckDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_raft_autopilot_config" {
			continue
		}

		client, e := provider.GetClient(rs.Primary, testProvider.Meta())
		if e != nil {
			return e
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

func testAccRaftAutopilotConfig_updated(cleanup, disableUpgrade bool, dsThresh, lcThresh, stabTime string, logs, quorum int) string {
	return fmt.Sprintf(`
resource "vault_raft_autopilot" "test" {
  cleanup_dead_servers = %t
  disable_upgrade_migration = %t
  dead_server_last_contact_threshold = "%s"
  last_contact_threshold = "%s"
  server_stabilization_time = "%s"
  max_trailing_logs = %d
  min_quorum = %d
}`, cleanup, disableUpgrade, dsThresh, lcThresh, stabTime, logs, quorum)
}
