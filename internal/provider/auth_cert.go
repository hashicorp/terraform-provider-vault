// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

// GetCertLoginSchema for the cert authentication engine.
func GetCertLoginSchema(authField string) *schema.Schema {
	return getLoginSchema(
		authField,
		"Login to vault using the cert method",
		GetCertLoginSchemaResource,
	)
}

// GetCertLoginSchemaResource for the cert authentication engine.
func GetCertLoginSchemaResource(authField string) *schema.Resource {
	return mustAddLoginSchema(&schema.Resource{
		Schema: map[string]*schema.Schema{
			consts.FieldName: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Name of the certificate's role",
			},
			consts.FieldCertFile: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Path to a file containing the client certificate.",
			},
			consts.FieldKeyFile: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Path to a file containing the private key that the certificate was issued for.",
			},
		},
	}, consts.MountTypeCert)
}

type AuthLoginCert struct {
	AuthLoginCommon
}

// MountPath for the cert authentication engine.
func (l *AuthLoginCert) MountPath() string {
	if l.mount == "" {
		return l.Method()
	}
	return l.mount
}

// LoginPath for the cert authentication engine.
func (l *AuthLoginCert) LoginPath() string {
	return fmt.Sprintf("auth/%s/login", l.MountPath())
}

func (l *AuthLoginCert) Init(d *schema.ResourceData, authField string) error {
	if err := l.AuthLoginCommon.Init(d, authField); err != nil {
		return err
	}

	// these fields come from the top level provider schema, and are global to all connections.
	// it does not seem to make sense to update the cert_login schema to include them at this time.
	for _, field := range []string{
		consts.FieldCACertFile,
		consts.FieldCACertDir,
		consts.FieldSkipTLSVerify,
		consts.FieldTLSServerName,
	} {
		if v, ok := d.GetOk(field); ok && v != nil {
			l.params[field] = v
		}
	}

	return nil
}

// Method name for the cert authentication engine.
func (l *AuthLoginCert) Method() string {
	return consts.AuthMethodCert
}

// Login using the cert authentication engine.
func (l *AuthLoginCert) Login(client *api.Client) (*api.Secret, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}

	c, err := client.Clone()
	if err != nil {
		return nil, err
	}

	tlsConfig := &api.TLSConfig{
		Insecure: false,
	}

	if v, ok := l.params[consts.FieldCACertFile]; ok {
		tlsConfig.CACert = v.(string)
	}

	if v, ok := l.params[consts.FieldCACertDir]; ok {
		tlsConfig.CAPath = v.(string)
	}

	if v, ok := l.params[consts.FieldCertFile]; ok {
		tlsConfig.ClientCert = v.(string)
	}

	if v, ok := l.params[consts.FieldKeyFile]; ok {
		tlsConfig.ClientKey = v.(string)
	}

	if v, ok := l.params[consts.FieldTLSServerName]; ok {
		tlsConfig.TLSServerName = v.(string)
	}

	if v, ok := l.params[consts.FieldSkipTLSVerify]; ok {
		tlsConfig.Insecure = v.(bool)
	}

	config := c.CloneConfig()
	if err := config.ConfigureTLS(tlsConfig); err != nil {
		return nil, err
	}

	c, err = api.NewClient(config)
	if err != nil {
		return nil, err
	}

	if config.CloneHeaders {
		c.SetHeaders(client.Headers())
	}

	params := make(map[string]interface{})
	if v, ok := l.params[consts.FieldName]; ok {
		// the cert auth API only supports the role name parameter
		params[consts.FieldName] = v
	}

	return l.login(c, l.LoginPath(), params)
}
