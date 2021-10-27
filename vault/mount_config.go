package vault

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func mountConfigSchema() *schema.Schema {
	additionalFields := map[string]*schema.Schema{
		"force_no_cache": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Disable caching.",
		},
	}
	return sharedAuthAndMountSchema(additionalFields)
}
