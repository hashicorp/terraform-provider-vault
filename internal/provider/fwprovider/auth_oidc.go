package fwprovider

import (
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func AuthLoginOIDCSchema() schema.Block {
	return mustAddLoginSchema(&schema.ListNestedBlock{
		Description: "Login to vault using the oidc method",
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				consts.FieldRole: schema.StringAttribute{
					Required:    true,
					Description: "Name of the login role.",
				},

				consts.FieldCallbackListenerAddress: schema.StringAttribute{
					Optional:    true,
					Description: "The callback listener's address. Must be a valid URI without the path.",
					// ValidateDiagFunc: GetValidateDiagURI([]string{"tcp"}),
				},
				consts.FieldCallbackAddress: schema.StringAttribute{
					Optional:    true,
					Description: "The callback address. Must be a valid URI without the path.",
					// ValidateDiagFunc: GetValidateDiagURI([]string{"http", "https"}),
				},
			},
		},
	}, consts.MountTypeGCP)
}
