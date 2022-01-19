package vault

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func kvV2ConfigDataSource() *schema.Resource {
	return &schema.Resource{
		Read: kvV2ConfigDataSourceRead,
		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The kv-v2 backend mount point.",
			},
			"max_versions": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "The number of versions to keep per key.",
			},
			"cas_required": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: " If true all keys will require the cas parameter to be set on all write requests.",
			},
			"delete_version_after": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "If set, specifies the length of time before a version is deleted. Accepts Go duration format string.",
			},
		},
	}
}

func kvV2ConfigDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	targetPath := d.Get("path").(string)
	return kvV2ConfigReadByPath(d, meta, targetPath)
}
