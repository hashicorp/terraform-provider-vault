// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

const transformRewrapRoleEndpoint = "/transform/rewrap/{role_name}"

func transformRewrapDataSource() *schema.Resource {
	return &schema.Resource{
		Read: provider.ReadWrapper(readTransformRewrapRoleResource),
		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Path to backend from which to retrieve data.",
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			"batch_input": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeMap},
				Optional:    true,
				Description: "Specifies a list of items to be re-encoded in a single batch. If this parameter is set, the top-level parameters 'value', 'transformation', 'decode_transformation', 'tweak', and 'decode_tweak' will be ignored. Each batch item within the list can specify these parameters instead.",
			},
			"batch_results": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeMap},
				Computed:    true,
				Description: "The result of rewrapping batch_input.",
			},
			"decode_transformation": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The FPE transformation to use to decode the value.",
			},
			"decode_tweak": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The tweak value to use for decoding. Only applicable for FPE transformations with a supplied tweak source.",
			},
			"encoded_value": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The result of rewrapping a value.",
			},
			"role_name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The name of the role.",
			},
			"transformation": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The FPE transformation to use for re-encrypting the value.",
			},
			"tweak": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The tweak value to use for re-encrypting. Only applicable for FPE transformations with a supplied tweak source.",
			},
			"value": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The value to rewrap.",
			},
		},
	}
}

func readTransformRewrapRoleResource(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}
	path := d.Get("path").(string)
	vaultPath := util.ParsePath(path, transformRewrapRoleEndpoint, d)

	data := make(map[string]interface{})
	if val, ok := d.GetOk("role_name"); ok {
		data["role_name"] = val
	}
	if val, ok := d.GetOk("batch_input"); ok {
		data["batch_input"] = val
	} else {
		if val, ok := d.GetOk("decode_transformation"); ok {
			data["decode_transformation"] = val
		}
		if val, ok := d.GetOk("transformation"); ok {
			data["transformation"] = val
		}
		if val, ok := d.GetOk("decode_tweak"); ok {
			data["decode_tweak"] = val
		}
		if val, ok := d.GetOk("tweak"); ok {
			data["tweak"] = val
		}
		if val, ok := d.GetOk("value"); ok {
			data["value"] = val
		}
	}
	log.Printf("[DEBUG] Writing %q", vaultPath)
	resp, err := client.Logical().Write(vaultPath, data)
	if err != nil {
		if util.Is404(err) {
			log.Printf("[WARN] %q not found, removing from state", vaultPath)
			d.SetId("")
			return nil
		}
		return fmt.Errorf("error writing %q: %s", vaultPath, err)
	}
	if resp == nil {
		d.SetId("")
		return nil
	}
	d.SetId(vaultPath)
	batchResults, batchOk := resp.Data["batch_results"]
	if batchOk {
		if err := d.Set("batch_results", batchResults); err != nil {
			return fmt.Errorf("error setting batch_results: %w", err)
		}
	} else {
		if err := d.Set("encoded_value", resp.Data["encoded_value"]); err != nil {
			return fmt.Errorf("error setting encoded_value: %w", err)
		}
		if err := d.Set("tweak", resp.Data["tweak"]); err != nil {
			return fmt.Errorf("error setting tweak: %w", err)
		}
	}
	return nil
}
