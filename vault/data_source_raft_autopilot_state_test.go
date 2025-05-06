// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAccDataSourceRaftAutoPilotState assumes that a raft cluster exists with
// autopilot_redundancy_zone configured for each node
// see: https://developer.hashicorp.com/vault/docs/enterprise/redundancy-zones
func TestAccDataSourceRaftAutoPilotState(t *testing.T) {
	ds := "data.vault_raft_autopilot_state.test"
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		PreCheck: func() {
			testutil.SkipTestEnvSet(t, "SKIP_RAFT_TESTS")
			testutil.TestEntPreCheck(t)
		},
		Steps: []resource.TestStep{
			{
				Config: testDataSourceRaftAutoPilotStateConfig(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(ds, consts.FieldFailureTolerance),
					resource.TestCheckResourceAttr(ds, consts.FieldHealthy, "true"),
					resource.TestCheckResourceAttrSet(ds, consts.FieldLeader),
					resource.TestCheckResourceAttrSet(ds, consts.FieldOptimisticFailureTolerance),
					resource.TestCheckResourceAttrSet(ds, consts.FieldRedundancyZonesJSON),
					resource.TestCheckResourceAttrSet(ds, consts.FieldServersJSON),
					resource.TestCheckResourceAttrSet(ds, consts.FieldUpgradeInfoJSON),
					resource.TestCheckResourceAttrSet(ds, consts.FieldVoters+".#"),
				),
			},
		},
	})
}

func testDataSourceRaftAutoPilotStateConfig() string {
	return `
resource "vault_raft_autopilot" "test" {}

data "vault_raft_autopilot_state" "test" {}
`
}
