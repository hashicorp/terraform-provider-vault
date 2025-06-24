// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package fwprovider

import (
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func AuthLoginAzureSchema() schema.Block {
	return mustAddLoginSchema(&schema.ListNestedBlock{
		Description: "Login to vault using the azure method",
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				consts.FieldJWT: schema.StringAttribute{
					Optional: true,
					Description: "A signed JSON Web Token. If not specified on will be " +
						"created automatically",
				},
				consts.FieldRole: schema.StringAttribute{
					Required:    true,
					Description: "Name of the login role.",
				},
				consts.FieldSubscriptionID: schema.StringAttribute{
					Required: true,
					Description: "The subscription ID for the machine that generated the MSI token. " +
						"This information can be obtained through instance metadata.",
				},
				consts.FieldResourceGroupName: schema.StringAttribute{
					Required: true,
					Description: "The resource group for the machine that generated the MSI token. " +
						"This information can be obtained through instance metadata.",
				},
				consts.FieldVMName: schema.StringAttribute{
					Optional: true,
					Description: "The virtual machine name for the machine that generated the MSI token. " +
						"This information can be obtained through instance metadata.",
				},
				consts.FieldVMSSName: schema.StringAttribute{
					Optional: true,
					Description: "The virtual machine scale set name for the machine that generated " +
						"the MSI token. This information can be obtained through instance metadata.",
					Validators: []validator.String{
						stringvalidator.ConflictsWith(
							path.MatchRelative().AtName(consts.FieldVMName),
						),
					},
				},
				consts.FieldTenantID: schema.StringAttribute{
					Optional: true,
					Description: "Provides the tenant ID to use in a multi-tenant " +
						"authentication scenario.",
					Validators: []validator.String{
						stringvalidator.ConflictsWith(
							path.MatchRelative().AtName(consts.FieldJWT),
						),
					},
				},
				consts.FieldClientID: schema.StringAttribute{
					Optional:    true,
					Description: "The identity's client ID.",
					Validators: []validator.String{
						stringvalidator.ConflictsWith(
							path.MatchRelative().AtName(consts.FieldJWT),
						),
					},
				},
				consts.FieldScope: schema.StringAttribute{
					Optional:    true,
					Description: "The scopes to include in the token request.",
					Validators: []validator.String{
						stringvalidator.ConflictsWith(
							path.MatchRelative().AtName(consts.FieldJWT),
						),
					},
				},
			},
		},
	}, consts.MountTypeAzure)
}
