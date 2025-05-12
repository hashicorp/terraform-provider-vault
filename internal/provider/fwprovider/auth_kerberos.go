// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package fwprovider

import (
	"github.com/hashicorp/terraform-plugin-framework-validators/boolvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/validators"
)

func AuthLoginKerberosSchema() schema.Block {
	return mustAddLoginSchema(&schema.ListNestedBlock{
		Description: "Login to vault using the kerberos method",
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				consts.FieldToken: schema.StringAttribute{
					Optional:    true,
					Description: "Simple and Protected GSSAPI Negotiation Mechanism (SPNEGO) token",
					Validators: []validator.String{
						validators.KRBNegTokenValidator(),
					},
				},
				consts.FieldUsername: schema.StringAttribute{
					Optional:    true,
					Description: "The username to login into Kerberos with.",
					Validators: []validator.String{
						stringvalidator.ConflictsWith(
							path.MatchRelative().AtName(consts.FieldToken),
						),
					},
				},
				consts.FieldService: schema.StringAttribute{
					Optional:    true,
					Description: "The service principle name.",
					Validators: []validator.String{
						stringvalidator.ConflictsWith(
							path.MatchRelative().AtName(consts.FieldToken),
						),
					},
				},
				consts.FieldRealm: schema.StringAttribute{
					Optional:    true,
					Description: "The Kerberos server's authoritative authentication domain",
					Validators: []validator.String{
						stringvalidator.ConflictsWith(
							path.MatchRelative().AtName(consts.FieldToken),
						),
					},
				},
				consts.FieldKRB5ConfPath: schema.StringAttribute{
					Optional:    true,
					Description: "A valid Kerberos configuration file e.g. /etc/krb5.conf.",
					Validators: []validator.String{
						validators.FileExistsValidator(),
						stringvalidator.ConflictsWith(
							path.MatchRelative().AtName(consts.FieldToken),
						),
					},
				},
				consts.FieldKeytabPath: schema.StringAttribute{
					Optional:    true,
					Description: "The Kerberos keytab file containing the entry of the login entity.",
					Validators: []validator.String{
						validators.FileExistsValidator(),
						stringvalidator.ConflictsWith(
							path.MatchRelative().AtName(consts.FieldToken),
						),
					},
				},
				consts.FieldDisableFastNegotiation: schema.BoolAttribute{
					Optional: true,
					Validators: []validator.Bool{
						boolvalidator.ConflictsWith(
							path.MatchRelative().AtName(consts.FieldToken),
						),
					},
					Description: "Disable the Kerberos FAST negotiation.",
				},
				consts.FieldRemoveInstanceName: schema.BoolAttribute{
					Optional: true,
					Validators: []validator.Bool{
						boolvalidator.ConflictsWith(
							path.MatchRelative().AtName(consts.FieldToken),
						),
					},
					Description: "Strip the host from the username found in the keytab.",
				},
			},
		},
	}, consts.MountTypeKerberos)
}
