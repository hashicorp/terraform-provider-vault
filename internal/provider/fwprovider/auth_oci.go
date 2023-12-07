package fwprovider

import (
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

const (
	ociAuthTypeInstance = "instance"
	ociAuthTypeAPIKeys  = "apikey"
)

func AuthLoginOCISchema() schema.Block {
	return mustAddLoginSchema(&schema.ListNestedBlock{
		Description: "Login to vault using the OCI method",
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				consts.FieldRole: schema.StringAttribute{
					Required:    true,
					Description: "Name of the login role.",
				},
				consts.FieldAuthType: schema.StringAttribute{
					Required:    true,
					Description: "Authentication type to use when getting OCI credentials.",
					Validators: []validator.String{
						stringvalidator.OneOf([]string{ociAuthTypeInstance, ociAuthTypeAPIKeys}...),
					},
				},
			},
		},
	}, consts.MountTypeOCI)
}
