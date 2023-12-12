package fwprovider

import (
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func AuthLoginTokenFileSchema() schema.Block {
	return mustAddLoginSchema(&schema.ListNestedBlock{
		Description: "Login to vault using ",
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				consts.FieldFilename: schema.StringAttribute{
					// can be set via an env var
					Optional: true,
					Description: "The name of a file containing a single " +
						"line that is a valid Vault token",
				},
			},
		},
	}, consts.MountTypeNone)
}
