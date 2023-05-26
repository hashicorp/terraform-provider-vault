// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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

func MustAddSchemaResource(s map[string]*schema.Resource, d map[string]*schema.Resource,
	f func(r *schema.Resource) *schema.Resource,
) {
	for n, r := range s {
		if f != nil {
			r = f(r)
		}
		if _, ok := d[n]; ok {
			panic(fmt.Sprintf("cannot add resource, Resource map already contains %q", n))
		}
		d[n] = r
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
