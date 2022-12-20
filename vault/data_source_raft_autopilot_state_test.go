package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestAccDataSourceRaftAutoPilotState(t *testing.T) {
	dataSourceName := "data.vault_raft_autopilot_state.test"
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceRaftAutoPilotStateConfig(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldFailureTolerance, "1"),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldHealthy, "true"),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldLeader, "foo"),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldOptimisticFailureTolerance, "2"),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldRedundancyZones, "bar"),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldServers, "baz"),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldUpgradeInfo, "qux"),
					resource.TestCheckResourceAttr(dataSourceName, consts.FieldVoters, "qoo"),
				),
			},
		},
	})
}

func testDataSourceRaftAutoPilotStateConfig() string {
	return fmt.Sprintf(`
resource "vault_raft_autopilot" "test" {
}

data "vault_raft_autopilot_state" "test" {
}
`)
}
