package mfa

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/terraform-provider-vault/util"
)

const (
	resourceNamePrefix = "vault_identity_mfa_"
	apiRoot            = "/identity/mfa"
	apiMethodRoot      = apiRoot + "/method"

	PathTypeName = iota
	PathTypeMethodID
)

type schemaResourceFunc func() (*schema.Resource, error)

var (
	resources = map[string]schemaResourceFunc{
		ResourceNameDuo:              GetDuoSchemaResource,
		ResourceNameTOTP:             GetTOTPSchemaResource,
		ResourceNameOKTA:             GetOKTASchemaResource,
		ResourceNamePingID:           GetPingIDSchemaResource,
		ResourceNameLoginEnforcement: GetLoginEnforcementSchemaResource,
	}
	defaultComputedOnlyFields = []string{
		consts.FieldType,
		consts.FieldMethodID,
		consts.FieldMountAccessor,
		consts.FieldNamespaceID,
		consts.FieldName,
	}
	defaultQuirksMap = map[string]string{
		consts.FieldID: consts.FieldUUID,
	}
)

type PathType int

func (t PathType) String() string {
	switch t {
	case PathTypeName:
		return "name"
	case PathTypeMethodID:
		return "method"
	default:
		return "unknown"
	}
}

type addSchemaFunc func(resource *schema.Resource) *schema.Resource

func GetResources() (map[string]*schema.Resource, error) {
	// TODO: will want to support vault.Description struct, punting on this for now.
	errs := multierror.Error{
		Errors: []error{},
	}

	res := map[string]*schema.Resource{}
	for n, f := range resources {
		r, err := f()
		if err != nil {
			errs.Errors = append(errs.Errors, err)
			continue
		}
		res[n] = r
	}

	return res, errs.ErrorOrNil()
}

func mustAddCommonSchema(r *schema.Resource) *schema.Resource {
	provider.MustAddNamespaceSchema(r.Schema)
	provider.MustAddSchema(r,
		map[string]*schema.Schema{
			consts.FieldUUID: {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Resource UUID.",
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
		},
	)

	return r
}

func mustAddCommonMFASchema(r *schema.Resource) *schema.Resource {
	common := map[string]*schema.Schema{
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
		consts.FieldMethodID: {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "Method ID.",
		},
	}

	provider.MustAddSchema(r, common)
	return r
}

func getRequestPath(method string, others ...string) string {
	return joinPath(apiRoot, append([]string{method}, others...)...)
}

func getMethodRequestPath(method string, others ...string) string {
	return joinPath(apiMethodRoot, append([]string{method}, others...)...)
}

func joinPath(root string, parts ...string) string {
	return strings.Join(append([]string{root}, parts...), consts.PathDelim)
}

type ContextFuncConfig struct {
	mu           sync.Mutex
	method       string
	m            map[string]*schema.Schema
	computedOnly []string
	quirksMap    map[string]string
	requireLock  bool
	requestPath  string
	pt           PathType
}

func (c *ContextFuncConfig) IDField() (string, error) {
	if c.IsPathTypeMethod() {
		return consts.FieldMethodID, nil
	} else if c.IsPathTypeName() {
		return consts.FieldName, nil
	}

	return "", fmt.Errorf("unsupported path type %s", c.pt)
}

func (c *ContextFuncConfig) PathType() PathType {
	return c.pt
}

func (c *ContextFuncConfig) Lock() {
	if c.requireLock {
		c.mu.Lock()
	}
}

func (c *ContextFuncConfig) Unlock() {
	if c.requireLock {
		c.mu.Unlock()
	}
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

func (c *ContextFuncConfig) IsPathTypeMethod() bool {
	return c.pt == PathTypeMethodID
}

func (c *ContextFuncConfig) IsPathTypeName() bool {
	return c.pt == PathTypeName
}

func (c *ContextFuncConfig) IsIDFromResponse() bool {
	if c.pt == PathTypeMethodID {
		return true
	}
	return false
}

func (c *ContextFuncConfig) GetRequestPathWithID(id string) (string, error) {
	base, err := c.GetRequestPathBase()
	if err != nil {
		return "", err
	}

	return joinPath(base, id), nil
}

func (c *ContextFuncConfig) GetRequestPathBase() (string, error) {
	if c.IsPathTypeMethod() {
		return getMethodRequestPath(c.Method()), nil
	} else if c.IsPathTypeName() {
		return getRequestPath(c.Method()), nil
	}

	return "", fmt.Errorf("no request path method for type %s", c.pt)
}

func (c *ContextFuncConfig) GetIDFromResponse(resp *api.Secret) (string, error) {
	// ID is derived from the response
	if resp == nil {
		return "", fmt.Errorf("response cannot be nil for path type %s", c.PathType())
	}

	idField, err := c.IDField()
	if err != nil {
		return "", err
	}

	v, ok := resp.Data[idField]
	if !ok {
		return "", fmt.Errorf("expected a value for %q", idField)
	}

	return c.id(idField, v)
}

func (c *ContextFuncConfig) GetIDFromResourceData(d *schema.ResourceData) (string, error) {
	idField, err := c.IDField()
	if err != nil {
		return "", err
	}

	v, ok := d.Get(idField).(string)
	if !ok {
		return "", fmt.Errorf("expected a value for %q", idField)
	}

	return c.id(idField, v)
}

func (c *ContextFuncConfig) id(f string, v interface{}) (string, error) {
	id, ok := v.(string)
	if !ok || id == "" {
		return "", fmt.Errorf("value for %q must be non-empty string", f)
	}
	return id, nil
}

func NewContextFuncConfig(method string, pt PathType, m map[string]*schema.Schema, computedOnly []string, quirksMap map[string]string) (*ContextFuncConfig, error) {
	if len(computedOnly) == 0 {
		computedOnly = defaultComputedOnlyFields
	}

	if quirksMap == nil {
		quirksMap = make(map[string]string, len(defaultQuirksMap))
	}

	for k, v := range defaultQuirksMap {
		quirksMap[k] = v
	}

	switch pt {
	case PathTypeName, PathTypeMethodID:
	default:
		return nil, fmt.Errorf("unsupported path type %s", pt)
	}

	config := &ContextFuncConfig{
		method:       method,
		pt:           pt,
		m:            m,
		computedOnly: computedOnly,
		quirksMap:    quirksMap,
		requireLock:  true,
	}

	return config, nil
}

func getMethodSchemaResource(s map[string]*schema.Schema, config *ContextFuncConfig) *schema.Resource {
	return getSchemaResource(s, config, mustAddCommonSchema, mustAddCommonMFASchema)
}

func getSchemaResource(s map[string]*schema.Schema, config *ContextFuncConfig, addFuncs ...addSchemaFunc) *schema.Resource {
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

	if len(addFuncs) == 0 {
		addFuncs = []addSchemaFunc{
			mustAddCommonSchema,
		}
	}

	for _, f := range addFuncs {
		r = f(r)
	}

	config.m = r.Schema

	return r
}

func GetCreateContextFunc(config *ContextFuncConfig) schema.CreateContextFunc {
	return func(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
		config.Lock()
		defer config.Unlock()

		c, dg := provider.GetClientDiag(d, meta)
		if dg != nil {
			return dg
		}

		idField, err := config.IDField()
		if err != nil {
			return diag.FromErr(err)
		}

		var path string
		if config.IsIDFromResponse() {
			p, err := config.GetRequestPathBase()
			if err != nil {
				return diag.FromErr(err)
			}
			path = p
		} else {
			p, err := config.GetRequestPathWithID(d.Get(idField).(string))
			if err != nil {
				return diag.FromErr(err)
			}
			path = p
		}

		resp, err := c.Logical().Write(path, config.GetRequestData(d))
		if err != nil {
			return diag.FromErr(err)
		}

		var rid string
		if config.IsIDFromResponse() {
			id, err := config.GetIDFromResponse(resp)
			if err != nil {
				return diag.FromErr(err)
			}

			rid = id
		} else {
			id, err := config.GetIDFromResourceData(d)
			if err != nil {
				return diag.FromErr(err)
			}

			rid = id
		}

		d.SetId(rid)

		return GetReadContextFunc(config)(ctx, d, meta)
	}
}

func GetUpdateContextFunc(config *ContextFuncConfig) schema.UpdateContextFunc {
	return func(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
		config.Lock()
		defer config.Unlock()

		c, dg := provider.GetClientDiag(d, meta)
		if dg != nil {
			return dg
		}

		id := d.Id()
		if id == "" {
			return diag.FromErr(fmt.Errorf("resource ID is empty"))
		}

		path, err := config.GetRequestPathWithID(id)
		if err != nil {
			return diag.FromErr(err)
		}

		// login MFA does not support partial updates unfortunately,
		// so we update() becomes very similar to create.
		if _, err := c.Logical().Write(path, config.GetRequestData(d)); err != nil {
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

		id := d.Id()
		if id == "" {
			return nil
		}

		path, err := config.GetRequestPathWithID(id)
		if err != nil {
			return diag.FromErr(err)
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

		if config.HasSchema(consts.FieldMethodID) {
			if err := d.Set(consts.FieldMethodID, id); err != nil {
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

		id := d.Id()
		if id == "" {
			return nil
		}

		path, err := config.GetRequestPathWithID(id)
		if err != nil {
			return diag.FromErr(err)
		}

		if _, err := c.Logical().Delete(path); err != nil {
			return diag.FromErr(err)
		}

		return nil
	}
}
