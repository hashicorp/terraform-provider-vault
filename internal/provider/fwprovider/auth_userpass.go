package fwprovider

import (
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func AuthLoginUserpassSchema() schema.Block {
	return mustAddLoginSchema(&schema.ListNestedBlock{
		Description: "Login to vault using ",
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				"filename": schema.StringAttribute{
					Required: true,
					Description: "The name of a file containing a single " +
						"line that is a valid Vault token",
				},
			},
		},
	}, consts.MountTypeNone)
}
