package vault

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func kvSecretListDataSourceV2() *schema.Resource {
	return &schema.Resource{
		ReadContext: kvSecretListDataSourceRead,

		Schema: map[string]*schema.Schema{
			"path": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Full KV-V2 path where secrets will be listed.",
				ValidateFunc: validateNoTrailingSlash,
			},

			"names": {
				Type:        schema.TypeList,
				Computed:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "List of all secret names.",
				Sensitive:   true,
			},
		},
	}
}
