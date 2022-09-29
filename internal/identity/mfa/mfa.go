package mfa

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
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
	defaultComputedOnlyFields = []string{
		consts.FieldType,
		consts.FieldMethodID,
		consts.FieldMountAccessor,
		consts.FieldNamespaceID,
		consts.FieldName,
	}
	defaultQuirkMap = map[string]string{
		consts.FieldID: consts.FieldUUID,
	}
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
			Type:        schema.TypeString,
			Computed:    true,
			Description: "Resource UUID.",
		},
		consts.FieldType: {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "MFA type.",
		},
		consts.FieldMountAccessor: {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "Mount accessor.",
		},
		consts.FieldName: {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "Method name.",
		},
		consts.FieldNamespaceID: {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "Method's namespace ID.",
		},
		consts.FieldNamespacePath: {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "Method's namespace path.",
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
	quirksMap    map[string]string
}

func (c *ContextFuncConfig) HasSchema(k string) bool {
	if c.m == nil {
		return false
	}

	_, ok := c.m[k]
	return ok
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

func (c *ContextFuncConfig) GetSecretFields() []string {
	var fields []string
	if c.m == nil {
		return fields
	}

	for k, s := range c.m {
		if !s.Computed && s.Sensitive && s.Required {
			fields = append(fields, k)
		}
	}

	return fields
}

func (c *ContextFuncConfig) GetRequestData(d *schema.ResourceData) map[string]interface{} {
	return util.GetAPIRequestDataWithSlice(d, c.GetWriteFields())
}

func (c *ContextFuncConfig) Method() string {
	return c.method
}

func (c *ContextFuncConfig) GetRemappedField(k string) (string, bool) {
	if c.quirksMap != nil {
		if o, ok := c.quirksMap[k]; ok {
			return o, true
		}
	}
	return k, false
}

func NewContextFuncConfig(method string, m map[string]*schema.Schema, computedOnly []string, quirksMap map[string]string) *ContextFuncConfig {
	if len(computedOnly) == 0 {
		computedOnly = defaultComputedOnlyFields
	}

	if quirksMap == nil {
		quirksMap = make(map[string]string, len(defaultQuirkMap))
	}

	for k, v := range defaultQuirkMap {
		quirksMap[k] = v
	}

	return &ContextFuncConfig{
		method:       method,
		m:            m,
		computedOnly: computedOnly,
		quirksMap:    quirksMap,
	}
}

func getSchemaResource(s map[string]*schema.Schema, config *ContextFuncConfig) *schema.Resource {
	m := map[string]*schema.Schema{}
	for k, v := range s {
		m[k] = v
	}

	r := &schema.Resource{
		Schema:        m,
		CreateContext: GetCreateContextFunc(config),
		UpdateContext: GetUpdateContextFunc(config),
		ReadContext:   GetReadContextFunc(config),
		DeleteContext: GetDeleteContextFunc(config),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
	}

	mustAddCommonSchema(r)
	config.m = r.Schema

	return r
}

func GetCreateContextFunc(config *ContextFuncConfig) schema.CreateContextFunc {
	return func(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
		c, dg := provider.GetClientDiag(d, meta)
		if dg != nil {
			return dg
		}

		path := getRequestPath(config.Method())
		resp, err := c.Logical().Write(path, config.GetRequestData(d))
		if err != nil {
			return diag.FromErr(err)
		}

		if resp == nil {
			return diag.FromErr(fmt.Errorf("nil response on write to path %q", path))
		}

		if v, ok := resp.Data[consts.FieldMethodID]; !ok {
			return diag.FromErr(fmt.Errorf("expected a value for %q", consts.FieldMethodID))
		} else {
			id, ok := v.(string)
			if id == "" || !ok {
				return diag.FromErr(fmt.Errorf("value for %q is empty or of the wrong type", consts.FieldMethodID))
			}
			d.SetId(id)
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

		id := d.Id()
		if id == "" {
			return diag.FromErr(fmt.Errorf("resource ID is empty"))
		}

		// login MFA does not support partial updates unfortunately,
		// so we update() becomes very similar to create.
		_, err := c.Logical().Write(getRequestPath(config.Method(), id), config.GetRequestData(d))
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
		id := d.Id()
		if id == "" {
			return nil
		} else {
			path = getRequestPath(config.Method(), id)
		}

		resp, err := c.Logical().Read(path)
		if err != nil {
			return diag.FromErr(err)
		}

		if resp == nil {
			d.SetId("")
			return nil
		}

		for k, v := range resp.Data {
			sk := k
			if o, ok := config.GetRemappedField(k); ok {
				sk = o
			}

			if !config.HasSchema(sk) {
				log.Printf("[WARN] Skipping unsupported response field %q, skipping it", k)
				continue
			}

			if err := d.Set(sk, v); err != nil {
				return diag.FromErr(err)
			}
		}

		// handle sensitive values that are not returned from Vault
		for _, k := range config.GetSecretFields() {
			if _, ok := resp.Data[k]; ok {
				continue
			}

			if err := d.Set(k, d.Get(k)); err != nil {
				return diag.FromErr(err)
			}
		}

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
