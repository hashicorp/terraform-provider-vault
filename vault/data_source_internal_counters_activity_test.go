package vault

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/testutil"
)

// TestAccDataSourceInternalCountersActivityState assumes that a raft cluster exists with
// autopilot_redundancy_zone configured for each node
// see: https://developer.hashicorp.com/vault/docs/enterprise/redundancy-zones
func TestAccDataSourceInternalCountersActivityState(t *testing.T) {
	ds := "data.vault_internal_counters_activity_state.test"
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck: func() {
			testutil.SkipTestEnvSet(t, "SKIP_ACTIVITY_TESTS")
			testutil.TestEntPreCheck(t)
		},
		Steps: []resource.TestStep{
			{
				Config: testDataSourceInternalCountersActivityStateConfig(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(ds, consts.FieldByNamespace),
					resource.TestCheckResourceAttrSet(ds, consts.FieldEndTime),
					resource.TestCheckResourceAttrSet(ds, consts.FieldMonths),
					resource.TestCheckResourceAttrSet(ds, consts.FieldData),
					resource.TestCheckResourceAttrSet(ds, consts.FieldStartTime),
				),
			},
		},
	})
}

func testDataSourceInternalCountersActivityStateConfig() string {
	return `
resource "vault_internal_counters_activity" "test" {}

data "vault_internal_counters_activity" "test" {}
`
}
