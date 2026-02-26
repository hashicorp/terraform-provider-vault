// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package fwprovider

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/boolvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/validators"
)

func mustAddLoginSchema(s *schema.ListNestedBlock, defaultMount string) schema.Block {
	m := map[string]schema.Attribute{
		consts.FieldNamespace: schema.StringAttribute{
			Optional: true,
			Description: fmt.Sprintf(
				"The authentication engine's namespace. Conflicts with %s",
				consts.FieldUseRootNamespace,
			),
			Validators: []validator.String{
				stringvalidator.ConflictsWith(
					path.MatchRelative().AtParent().AtName(consts.FieldUseRootNamespace),
				),
			},
		},
		consts.FieldUseRootNamespace: schema.BoolAttribute{
			Optional: true,
			Description: fmt.Sprintf(
				"Authenticate to the root Vault namespace. Conflicts with %s",
				consts.FieldNamespace,
			),
			Validators: []validator.Bool{
				boolvalidator.ConflictsWith(
					path.MatchRelative().AtParent().AtName(consts.FieldNamespace),
				),
			},
		},
	}
	if defaultMount != consts.MountTypeNone {
		m[consts.FieldMount] = &schema.StringAttribute{
			Optional:    true,
			Description: "The path where the authentication engine is mounted.",
			Validators: []validator.String{
				validators.PathValidator(),
			},
		}
	}

	for k, v := range m {
		if _, ok := s.NestedObject.Attributes[k]; ok {
			panic(fmt.Sprintf("cannot add schema field %q,  already exists in the Schema map", k))
		}

		s.NestedObject.Attributes[k] = v
	}

	return s
}
