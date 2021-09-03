package vault

import (
	"github.com/hashicorp/terraform-provider-vault/util"
	"testing"

	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/vault/api"
)

func TestAccRaftSnapshotAgentConfig_basic(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-test-raft-snapshot")
	resource.Test(t, resource.TestCase{
		Providers:    testProviders,
		PreCheck:     func() { util.TestEntPreCheck(t) },
		CheckDestroy: testAccRaftSnapshotAgentConfigCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccRaftSnapshotAgentConfig_basic(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "name", name),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "interval_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "retain", "1"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "path_prefix", "/tmp"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "file_prefix", "vault-snapshot"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "storage_type", "local"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "local_max_space", "4096"),
				),
			},
			{
				Config: testAccRaftSnapshotAgentConfig_updated(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "name", name),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "interval_seconds", "7200"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "retain", "1"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "path_prefix", "/tmp"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "file_prefix", "vault-snapshot"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "storage_type", "local"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "local_max_space", "4096"),
				),
			},
		},
	})
}

func TestAccRaftSnapshotAgentConfig_import(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-test-raft-snapshot")
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { util.TestEntPreCheck(t) },
		Providers:    testProviders,
		CheckDestroy: testAccRaftSnapshotAgentConfigCheckDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccRaftSnapshotAgentConfig_basic(name),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "name", name),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "interval_seconds", "3600"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "retain", "1"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "path_prefix", "/tmp"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "file_prefix", "vault-snapshot"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "storage_type", "local"),
					resource.TestCheckResourceAttr("vault_raft_snapshot_agent_config.test", "local_max_space", "4096"),
				),
			},
			{
				ResourceName:      "vault_raft_snapshot_agent_config.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccRaftSnapshotAgentConfigCheckDestroy(s *terraform.State) error {
	client := testProvider.Meta().(*api.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "vault_raft_snapshot_agent_config" {
			continue
		}
		snapshot, err := client.Logical().Read(rs.Primary.ID)
		if err != nil {
			return err
		}
		if snapshot != nil {
			return fmt.Errorf("library %q still exists", rs.Primary.ID)
		}
	}
	return nil
}

func testAccRaftSnapshotAgentConfig_basic(name string) string {
	return fmt.Sprintf(`
resource "vault_raft_snapshot_agent_config" "test" {
  name = "%s"
  interval_seconds = 3600
  retain = 1
  path_prefix = "/tmp"
  storage_type = "local"
  local_max_space = 4096
}`, name)
}

func testAccRaftSnapshotAgentConfig_updated(name string) string {
	return fmt.Sprintf(`
resource "vault_raft_snapshot_agent_config" "test" {
  name = "%s"
  interval_seconds = 7200
  retain = 1
  path_prefix = "/tmp"
  storage_type = "local"
  local_max_space = 4096
}`, name)
}
