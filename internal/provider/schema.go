package provider

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func GetNamespaceSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		consts.FieldNamespace: {
			Type:         schema.TypeString,
			Optional:     true,
			ForceNew:     true,
			Description:  "Target namespace. (requires Enterprise)",
			ValidateFunc: ValidateNoLeadingTrailingSlashes,
		},
	}
}

func MustAddNamespaceSchema(d map[string]*schema.Schema) {
	for k, s := range GetNamespaceSchema() {
		mustAddSchema(k, s, d)
	}
}
