// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func resourcePolicyResourceV0() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"policy": {
				Type:     schema.TypeString,
				Required: true,
			},
			consts.FieldAllowOverwrite: {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},
		},
	}
}

func resourcePolicyUpgradeV0(_ context.Context, rawState map[string]interface{}, _ interface{}) (map[string]interface{}, error) {
	log.Printf("[DEBUG] Upgrading vault_policy state from v0 to v1")
	log.Printf("[DEBUG] Attributes before migration: %#v", rawState)

	// Remove allow_overwrite from state as it's a config-only parameter
	delete(rawState, consts.FieldAllowOverwrite)

	log.Printf("[DEBUG] Attributes after migration: %#v", rawState)
	return rawState, nil
}
