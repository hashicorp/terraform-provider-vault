package fwprovider

import (
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func AuthLoginRadiusSchema() schema.Block {
	return mustAddLoginSchema(&schema.ListNestedBlock{
		Description: "Login to vault using the radius method",
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				consts.FieldUsername: schema.StringAttribute{
					Description: "The Radius username.",
					Optional:    true,
				},
				consts.FieldPassword: schema.StringAttribute{
					Optional:    true,
					Description: "The Radius password for username.",
				},
			},
		},
	}, consts.MountTypeGCP)
}
