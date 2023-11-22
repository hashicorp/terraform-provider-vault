package fwprovider

import (
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/validators"
)

func AuthLoginGCPSchema() schema.Block {
	return mustAddLoginSchema(&schema.ListNestedBlock{
		Description: "Login to vault using the gcp method",
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				consts.FieldRole: schema.StringAttribute{
					Optional:    true,
					Description: "Name of the login role.",
				},
				consts.FieldJWT: schema.StringAttribute{
					Optional:    true,
					Description: "A signed JSON Web Token.",
					Validators: []validator.String{
						stringvalidator.ConflictsWith(
							path.MatchRelative().AtName(consts.FieldCredentials),
						),
					},
				},
				consts.FieldCredentials: schema.StringAttribute{
					Optional:    true,
					Description: "Path to the Google Cloud credentials file.",
					Validators: []validator.String{
						stringvalidator.ConflictsWith(
							path.MatchRelative().AtName(consts.FieldJWT),
						),
						stringvalidator.LengthAtLeast(1),
						validators.GCPCredentialsValidator(),
					},
				},
				consts.FieldServiceAccount: schema.StringAttribute{
					Optional:    true,
					Description: "IAM service account.",
					Validators: []validator.String{
						stringvalidator.ConflictsWith(
							path.MatchRelative().AtName(consts.FieldJWT),
						),
					},
				},
			},
		},
	}, consts.MountTypeGCP)
}
