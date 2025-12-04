// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/helper"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
)

func init() {
	field := consts.FieldAuthLoginCert
	if err := globalAuthLoginRegistry.Register(field,
		func(r *schema.ResourceData) (AuthLogin, error) {
			a := &AuthLoginCert{}
			return a.Init(r, field)
		}, GetCertLoginSchema); err != nil {
		panic(err)
	}
}

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
	}, authField, consts.MountTypeCert)
}

var _ AuthLogin = (*AuthLoginCert)(nil)

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

func (l *AuthLoginCert) Init(d *schema.ResourceData, authField string) (AuthLogin, error) {
	if err := l.AuthLoginCommon.Init(d, authField,
		func(data *schema.ResourceData, params map[string]interface{}) error {
			return l.checkRequiredFields(d, params, consts.FieldCertFile, consts.FieldKeyFile)
		},
	); err != nil {
		return nil, err
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

	return l, nil
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

	config := client.CloneConfig()
	tlsConfig := config.TLSConfig()
	if tlsConfig == nil {
		return nil, fmt.Errorf("clone api.Config's TLSConfig is nil")
	}

	var clientCertFile string
	var clientKeyFile string
	if v, ok := l.params[consts.FieldCertFile]; ok {
		clientCertFile = v.(string)
	}

	if v, ok := l.params[consts.FieldKeyFile]; ok {
		clientKeyFile = v.(string)
	}

	if v, ok := l.params[consts.FieldSkipTLSVerify]; ok {
		tlsConfig.InsecureSkipVerify = v.(bool)
	}

	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		return nil, err
	}

	tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return &clientCert, nil
	}

	switch t := config.HttpClient.Transport.(type) {
	case *helper.TransportWrapper:
		if err := t.SetTLSConfig(tlsConfig); err != nil {
			return nil, err
		}
	case *http.Transport:
		t.TLSClientConfig = tlsConfig
	default:
		return nil, fmt.Errorf("HTTPClient has unsupported Transport type %T", t)
	}

	params := make(map[string]interface{})
	if v, ok := l.params[consts.FieldName]; ok {
		// the cert auth API only supports the role name parameter
		params[consts.FieldName] = v
	}

	return l.login(c, l.LoginPath(), params)
}
