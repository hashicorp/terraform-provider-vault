package provider

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func MustAddSchema(r *schema.Resource, m map[string]*schema.Schema) {
	for k, s := range m {
		mustAddSchema(k, s, r.Schema)
	}
}

func mustAddSchema(k string, s *schema.Schema, d map[string]*schema.Schema) {
	if _, ok := d[k]; ok {
		panic(fmt.Sprintf("cannot add schema field %q,  already exists in the Schema map", k))
	}

	d[k] = s
}

func MustAddMountMigrationSchema(r *schema.Resource) *schema.Resource {
	MustAddSchema(r, map[string]*schema.Schema{
		consts.FieldDisableRemount: {
			Type:     schema.TypeBool,
			Optional: true,
			Default:  false,
			Description: "If set, opts out of mount migration " +
				"on path updates.",
		},
	})

	return r
}
