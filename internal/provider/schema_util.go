package provider

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func MustAddSchema(r *schema.Resource, m map[string]*schema.Schema) {
	for k, s := range m {
		if _, ok := r.Schema[k]; ok {
			panic(fmt.Sprintf("cannot add schema field %q,  already exists in the Schema map", k))
		}

		r.Schema[k] = s
	}
}
