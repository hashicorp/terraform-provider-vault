package vault

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var rgpPolicyAttributes = []string{"enforcement_level", "policy"}

func rgpPolicyResource() *schema.Resource {
	return &schema.Resource{
		Create: rgpPolicyWrite,
		Update: rgpPolicyWrite,
		Delete: rgpPolicyDelete,
		Read:   rgpPolicyRead,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the policy",
			},

			"enforcement_level": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Enforcement level of Sentinel policy. Can be one of: 'advisory', 'soft-mandatory' or 'hard-mandatory'",
				ValidateFunc: ValidateSentinelEnforcementLevel,
			},

			"policy": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The policy document",
			},
		},
	}
}

func rgpPolicyWrite(d *schema.ResourceData, meta interface{}) error {
	return sentinelPolicyWrite("rgp", rgpPolicyAttributes, d, meta)
}

func rgpPolicyDelete(d *schema.ResourceData, meta interface{}) error {
	return sentinelPolicyDelete("rgp", d, meta)
}

func rgpPolicyRead(d *schema.ResourceData, meta interface{}) error {
	return sentinelPolicyRead("rgp", rgpPolicyAttributes, d, meta)
}
