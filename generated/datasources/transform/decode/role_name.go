package decode

// DO NOT EDIT
// This code is generated.

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

const rolenameEndpoint = "/transform/decode/{role_name}"

func RolenameDataSource() *schema.Resource {
	return &schema.Resource{
		Read: rolenameReadDataSource,
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
				Elem:        &schema.Schema{Type: schema.TypeString},
				Optional:    true,
				Description: "Specifies a list of items to be decoded in a single batch. If this parameter is set, the top-level parameters &#39;value&#39;, &#39;transformation&#39; and &#39;tweak&#39; will be ignored. Each batch item within the list can specify these parameters instead.",
				Computed:    true,
			},
			"role_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the role.",
				Computed:    true,
			},
			"transformation": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The transformation to perform. If no value is provided and the role contains a single transformation, this value will be inferred from the role.",
				Computed:    true,
			},
			"tweak": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The tweak value to use. Only applicable for FPE transformations",
				Computed:    true,
			},
			"value": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The value in which to decode.",
				Computed:    true,
			},
		},
	}
}

func rolenameReadDataSource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string) + rolenameEndpoint

	log.Printf("[DEBUG] Reading config %q", path)
	resp, err := client.Logical().Write(path, nil)
	if err != nil {
		return fmt.Errorf("error reading config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read config %q", path)

	if resp == nil {
		d.SetId("")
		return nil
	}
	d.SetId(path)
	if err := d.Set("batch_input", resp.Data["batch_input"]); err != nil {
		return err
	}
	if err := d.Set("role_name", resp.Data["role_name"]); err != nil {
		return err
	}
	if err := d.Set("transformation", resp.Data["transformation"]); err != nil {
		return err
	}
	if err := d.Set("tweak", resp.Data["tweak"]); err != nil {
		return err
	}
	if err := d.Set("value", resp.Data["value"]); err != nil {
		return err
	}
	return nil
}
