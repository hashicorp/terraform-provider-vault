package encode

// DO NOT EDIT
// This code is generated.

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-vault/util"
	"github.com/hashicorp/vault/api"
)

const roleNameEndpoint = "/transform/encode/{role_name}"

func RoleNameDataSource() *schema.Resource {
	return &schema.Resource{
		Read: readRoleNameResource,
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
				Description: "Specifies a list of items to be encoded in a single batch. If this parameter is set, the parameters 'value', 'transformation' and 'tweak' will be ignored. Each batch item within the list can specify these parameters instead.",
			},
			"batch_results": {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeMap},
				Optional:    true,
				Computed:    true,
				Description: "The result of encoding batch_input.",
			},
			"encoded_value": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The result of encoding a value.",
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
				Description: "The transformation to perform. If no value is provided and the role contains a single transformation, this value will be inferred from the role.",
			},
			"tweak": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The tweak value to use. Only applicable for FPE transformations",
			},
			"value": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The value in which to encode.",
			},
		},
	}
}

func readRoleNameResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Get("path").(string)
	vaultPath := util.ParsePath(path, roleNameEndpoint, d)
	log.Printf("[DEBUG] Writing %q", vaultPath)

	data := make(map[string]interface{})
	if val, ok := d.GetOkExists("batch_input"); ok {
		data["batch_input"] = val
	}
	if val, ok := d.GetOkExists("role_name"); ok {
		data["role_name"] = val
	}
	if val, ok := d.GetOkExists("transformation"); ok {
		data["transformation"] = val
	}
	if val, ok := d.GetOkExists("tweak"); ok {
		data["tweak"] = val
	}
	if val, ok := d.GetOkExists("value"); ok {
		data["value"] = val
	}
	log.Printf("[DEBUG] Writing %q", vaultPath)
	resp, err := client.Logical().Write(vaultPath, data)
	if err != nil {
		return fmt.Errorf("error writing %q: %s", vaultPath, err)
	}
	if resp == nil {
		d.SetId("")
		return nil
	}
	d.SetId(vaultPath)
	if err := d.Set("batch_results", resp.Data["batch_results"]); err != nil {
		return err
	}
	if err := d.Set("encoded_value", resp.Data["encoded_value"]); err != nil {
		return err
	}
	return nil
}
