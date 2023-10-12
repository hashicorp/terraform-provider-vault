// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var egpPolicyAttributes = []string{"enforcement_level", "paths", "policy"}

func egpPolicyResource() *schema.Resource {
	return &schema.Resource{
		Create: egpPolicyWrite,
		Update: egpPolicyWrite,
		Delete: egpPolicyDelete,
		Read:   provider.ReadWrapper(egpPolicyRead),
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

			"paths": {
				Type: schema.TypeList,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Required:    true,
				Description: "List of paths to which the policy will be applied",
			},

			"policy": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The policy document",
			},
		},
	}
}

func egpPolicyWrite(d *schema.ResourceData, meta interface{}) error {
	return sentinelPolicyWrite("egp", egpPolicyAttributes, d, meta)
}

func egpPolicyDelete(d *schema.ResourceData, meta interface{}) error {
	return sentinelPolicyDelete("egp", d, meta)
}

func egpPolicyRead(d *schema.ResourceData, meta interface{}) error {
	return sentinelPolicyRead("egp", egpPolicyAttributes, d, meta)
}
