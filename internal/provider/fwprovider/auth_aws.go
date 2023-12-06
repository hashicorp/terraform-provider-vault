package fwprovider

import (
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func AuthLoginAWSSchema() schema.Block {
	return mustAddLoginSchema(&schema.ListNestedBlock{
		Description: "Login to vault using the AWS method",
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				consts.FieldRole: schema.StringAttribute{
					Required:    true,
					Description: `The Vault role to use when logging into Vault.`,
				},
				// static credential fields
				consts.FieldAWSAccessKeyID: schema.StringAttribute{
					Optional:    true,
					Description: `The AWS access key ID.`,
				},
				consts.FieldAWSSecretAccessKey: schema.StringAttribute{
					Optional:    true,
					Description: `The AWS secret access key.`,
				},
				consts.FieldAWSSessionToken: schema.StringAttribute{
					Optional:    true,
					Description: `The AWS session token.`,
				},
				consts.FieldAWSProfile: schema.StringAttribute{
					Optional:    true,
					Description: `The name of the AWS profile.`,
				},
				consts.FieldAWSSharedCredentialsFile: schema.StringAttribute{
					Optional:    true,
					Description: `Path to the AWS shared credentials file.`,
				},
				consts.FieldAWSWebIdentityTokenFile: schema.StringAttribute{
					Optional: true,
					Description: `Path to the file containing an OAuth 2.0 access token or OpenID ` +
						`Connect ID token.`,
				},
				// STS assume role fields
				consts.FieldAWSRoleARN: schema.StringAttribute{
					Optional: true,
					Description: `The ARN of the AWS Role to assume.` +
						`Used during STS AssumeRole`,
				},
				consts.FieldAWSRoleSessionName: schema.StringAttribute{
					Optional: true,
					Description: `Specifies the name to attach to the AWS role session. ` +
						`Used during STS AssumeRole`,
				},
				consts.FieldAWSRegion: schema.StringAttribute{
					Optional:    true,
					Description: `The AWS region.`,
				},
				consts.FieldAWSSTSEndpoint: schema.StringAttribute{
					Optional:    true,
					Description: `The STS endpoint URL.`,
					Validators:  []validator.String{},
					// ValidateDiagFunc: GetValidateDiagURI([]string{"https", "http"}),
				},
				consts.FieldAWSIAMEndpoint: schema.StringAttribute{
					Optional:    true,
					Description: `The IAM endpoint URL.`,
					// ValidateDiagFunc: GetValidateDiagURI([]string{"https", "http"}),
				},
				consts.FieldHeaderValue: schema.StringAttribute{
					Optional:    true,
					Description: `The Vault header value to include in the STS signing request.`,
				},
			},
		},
	}, consts.MountTypeAWS)
}
