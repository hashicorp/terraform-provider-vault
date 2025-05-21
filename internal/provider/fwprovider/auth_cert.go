// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package fwprovider

import (
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func AuthLoginCertSchema() schema.Block {
	return mustAddLoginSchema(&schema.ListNestedBlock{
		Description: "Login to vault using the cert method",
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				consts.FieldName: schema.StringAttribute{
					Optional:    true,
					Description: "Name of the certificate's role",
				},
				consts.FieldCertFile: schema.StringAttribute{
					Required:    true,
					Description: "Path to a file containing the client certificate.",
				},
				consts.FieldKeyFile: schema.StringAttribute{
					Required:    true,
					Description: "Path to a file containing the private key that the certificate was issued for.",
				},
			},
		},
	}, consts.MountTypeCert)
}
