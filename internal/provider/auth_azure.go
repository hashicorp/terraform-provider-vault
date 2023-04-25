// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

const defaultAzureScope = "https://management.azure.com/"

// GetAzureLoginSchema for the azure authentication engine.
func GetAzureLoginSchema(authField string) *schema.Schema {
	return getLoginSchema(
		authField,
		"Login to vault using the azure method",
		GetAzureLoginSchemaResource,
	)
}

// GetAzureLoginSchemaResource for the azure authentication engine.
func GetAzureLoginSchemaResource(authField string) *schema.Resource {
	return mustAddLoginSchema(&schema.Resource{
		Schema: map[string]*schema.Schema{
			consts.FieldJWT: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "A signed JSON Web Token. If not specified on will be " +
					"created automatically",
				DefaultFunc: schema.EnvDefaultFunc(consts.EnvVarAzureAuthJWT, nil),
			},
			consts.FieldRole: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the login role.",
			},
			consts.FieldSubscriptionID: {
				Type:     schema.TypeString,
				Required: true,
				Description: "The subscription ID for the machine that generated the MSI token. " +
					"This information can be obtained through instance metadata.",
			},
			consts.FieldResourceGroupName: {
				Type:     schema.TypeString,
				Required: true,
				Description: "The resource group for the machine that generated the MSI token. " +
					"This information can be obtained through instance metadata.",
			},
			consts.FieldVMName: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The virtual machine name for the machine that generated the MSI token. " +
					"This information can be obtained through instance metadata.",
			},
			consts.FieldVMSSName: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The virtual machine scale set name for the machine that generated " +
					"the MSI token. This information can be obtained through instance metadata.",
				ConflictsWith: []string{fmt.Sprintf("%s.0.%s", authField, consts.FieldVMName)},
			},
			consts.FieldTenantID: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "Provides the tenant ID to use in a multi-tenant " +
					"authentication scenario.",
				ConflictsWith: []string{fmt.Sprintf("%s.0.%s", authField, consts.FieldJWT)},
			},
			consts.FieldClientID: {
				Type:          schema.TypeString,
				Optional:      true,
				Description:   "The identity's client ID.",
				ConflictsWith: []string{fmt.Sprintf("%s.0.%s", authField, consts.FieldJWT)},
			},
			consts.FieldScope: {
				Type:          schema.TypeString,
				Optional:      true,
				Default:       defaultAzureScope,
				Description:   "The scopes to include in the token request.",
				ConflictsWith: []string{fmt.Sprintf("%s.0.%s", authField, consts.FieldJWT)},
			},
		},
	}, consts.MountTypeAzure)
}

type AuthLoginAzure struct {
	AuthLoginCommon
}

// MountPath for the azure authentication engine.
func (l *AuthLoginAzure) MountPath() string {
	if l.mount == "" {
		return l.Method()
	}
	return l.mount
}

// LoginPath for the azure authentication engine.
func (l *AuthLoginAzure) LoginPath() string {
	return fmt.Sprintf("auth/%s/login", l.MountPath())
}

func (l *AuthLoginAzure) Init(d *schema.ResourceData, authField string) error {
	if err := l.AuthLoginCommon.Init(d, authField); err != nil {
		return err
	}

	if err := l.checkRequiredFields(d, l.requiredParams()...); err != nil {
		return err
	}

	if err := l.checkFieldsOneOf(d, consts.FieldVMName, consts.FieldVMSSName); err != nil {
		return err
	}

	return nil
}

func (l *AuthLoginAzure) requiredParams() []string {
	return []string{consts.FieldRole, consts.FieldSubscriptionID, consts.FieldResourceGroupName}
}

// Method name for the azure authentication engine.
func (l *AuthLoginAzure) Method() string {
	return consts.AuthMethodAzure
}

// Login using the azure authentication engine.
func (l *AuthLoginAzure) Login(client *api.Client) (*api.Secret, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}

	params, err := l.copyParams(l.requiredParams()...)
	if err != nil {
		return nil, err
	}

	if v, ok := l.params[consts.FieldVMName]; ok {
		params[consts.FieldVMName] = v
	} else if v, ok := l.params[consts.FieldVMName]; ok {
		params[consts.FieldVMSSName] = v
	}

	ctx := context.Background()
	jwt, err := l.getJWT(ctx)
	if err != nil {
		return nil, err
	}

	params[consts.FieldJWT] = jwt
	return l.login(client, l.LoginPath(), params)
}

func (l *AuthLoginAzure) getJWT(ctx context.Context) (string, error) {
	if v, ok := l.params[consts.FieldJWT]; ok {
		return v.(string), nil
	}

	// attempt to get the token from Azure
	credOpts := &azidentity.ManagedIdentityCredentialOptions{}
	if v, ok := l.params[consts.FieldClientID]; ok {
		credOpts.ID = azidentity.ClientID(v.(string))
	}

	creds, err := azidentity.NewManagedIdentityCredential(credOpts)
	if err != nil {
		return "", err
	}

	var scopes []string
	if v, ok := l.params[consts.FieldScope].(string); ok {
		scopes = append(scopes, v)
	}

	tOpts := policy.TokenRequestOptions{
		Scopes: scopes,
	}
	if v, ok := l.params[consts.FieldTenantID]; ok {
		tOpts.TenantID = v.(string)
	}

	token, err := creds.GetToken(ctx, tOpts)
	if err != nil {
		return "", err
	}

	return token.Token, nil
}
