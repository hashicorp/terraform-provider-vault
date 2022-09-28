package mfa

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

const (
	resourceNamePrefix = "vault_identity_login_mfa_"
	apiRoot            = "/identity/mfa/method"
)

var (
	resources = map[string]func() *schema.Resource{
		ResourceNameDuo:    GetDuoSchemaResource,
		ResourceNameTOTP:   GetTOTPSchemaResource,
		ResourceNameOKTA:   GetOKTASchemaResource,
		ResourceNamePingID: GetPingIDSchemaResource,
	}
	defaultComputedOnly = []string{consts.FieldType}
)

func GetResources() map[string]*schema.Resource {
	// TODO: will want to support vault.Description struct, punting on this for now.
	r := map[string]*schema.Resource{}
	for n, f := range resources {
		r[n] = f()
	}

	return r
}

func mustAddCommonSchema(r *schema.Resource) *schema.Resource {
	common := map[string]*schema.Schema{
		consts.FieldUUID: {
			Type:             schema.TypeString,
			Computed:         true,
			Description:      "Resource UUID.",
			ValidateDiagFunc: provider.ValidateDiagUUID,
		},
		consts.FieldType: {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "MFA type.",
		},
	}
	provider.MustAddSchema(r, common)
	provider.MustAddNamespaceSchema(r.Schema)
	return r
}

func getRequestPath(method string, others ...string) string {
	parts := append([]string{apiRoot, method}, others...)
	return strings.Join(parts, consts.PathDelim)
}

type ContextFuncConfig struct {
	method       string
	m            map[string]*schema.Schema
	computedOnly []string
}

func (c *ContextFuncConfig) GetWriteFields() []string {
	computedOnly := make(map[string]bool, len(c.computedOnly))
	for _, k := range c.computedOnly {
		computedOnly[k] = true
	}

	var r []string
	for k := range c.m {
		if _, ok := computedOnly[k]; !ok {
			r = append(r, k)
		}
	}

	return r
}

func (c *ContextFuncConfig) Method() string {
	return c.method
}

func NewContextFuncConfig(method string, m map[string]*schema.Schema, computedOnly []string) *ContextFuncConfig {
	if len(computedOnly) == 0 {
		computedOnly = defaultComputedOnly
	}

	return &ContextFuncConfig{
		method:       method,
		m:            m,
		computedOnly: computedOnly,
	}
}

func GetCreateContextFunc(config *ContextFuncConfig) schema.CreateContextFunc {
	return func(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
		c, dg := provider.GetClientDiag(d, meta)
		if dg != nil {
			return dg
		}

		data := map[string]interface{}{}
		for _, k := range config.GetWriteFields() {
			if v, ok := d.GetOk(k); ok {
				data[k] = v
			}
		}

		_, err := c.Logical().Write(getRequestPath(config.Method()), data)
		if err != nil {
			return diag.FromErr(err)
		}

		return GetReadContextFunc(config)(ctx, d, meta)
	}
}

func GetUpdateContextFunc(config *ContextFuncConfig) schema.UpdateContextFunc {
	return func(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
		c, dg := provider.GetClientDiag(d, meta)
		if dg != nil {
			return dg
		}

		var id string
		if v, ok := d.GetOk(consts.FieldUUID); !ok {
			return diag.FromErr(fmt.Errorf("no value set for %q, cannot update the resource"))
		} else if v.(string) == "" {
			return diag.FromErr(fmt.Errorf("empty value set for %q, cannot update the resource"))
		} else {
			id = v.(string)
		}

		data := map[string]interface{}{}
		for _, k := range config.GetWriteFields() {
			if d.HasChange(k) {
				data[k] = d.Get(k)
			}
		}

		_, err := c.Logical().Write(getRequestPath(config.Method(), id), data)
		if err != nil {
			return diag.FromErr(err)
		}

		return GetReadContextFunc(config)(ctx, d, meta)
	}
}

func GetReadContextFunc(config *ContextFuncConfig) schema.ReadContextFunc {
	return func(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
		c, dg := provider.GetClientDiag(d, meta)
		if dg != nil {
			return dg
		}

		var path string
		if v, ok := d.GetOk(consts.FieldUUID); !ok {
			d.SetId("")
			return nil
		} else {
			path = getRequestPath(config.Method(), v.(string))
		}

		resp, err := c.Logical().Read(path)
		if err != nil {
			return diag.FromErr(err)
		}

		if resp == nil {
			d.SetId("")
			return nil
		}

		var id string
		for k, v := range resp.Data {
			if k == consts.FieldID {
				id = v.(string)
				k = consts.FieldUUID
			}
			if err := d.Set(k, v); err != nil {
				return diag.FromErr(err)
			}
		}

		if id == "" {
			return diag.FromErr(fmt.Errorf("response contained an empty value for %q", consts.FieldID))
		}

		d.SetId(id)

		return nil
	}
}

func GetDeleteContextFunc(config *ContextFuncConfig) schema.DeleteContextFunc {
	return func(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
		c, dg := provider.GetClientDiag(d, meta)
		if dg != nil {
			return dg
		}

		var path string
		if v, ok := d.GetOk(consts.FieldUUID); !ok {
			return nil
		} else {
			path = getRequestPath(config.Method(), v.(string))
		}

		if _, err := c.Logical().Delete(path); err != nil {
			return diag.FromErr(err)
		}

		return nil
	}
}
