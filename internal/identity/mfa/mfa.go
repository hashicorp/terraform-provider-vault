// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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

// GetResources returns a schema resource map for all resources configured
// in the slice of resources. It is meant to be called during Provider initialization.
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

// contextFuncConfig provides the necessary configuration that is required by any of
// any Get*ContextFunc factory functions.
type contextFuncConfig struct {
	mu                    sync.Mutex
	method                string
	m                     map[string]*schema.Schema
	apiValueGetters       map[string]util.VaultAPIValueGetter
	defaultAPIValueGetter util.VaultAPIValueGetter
	computedOnly          []string
	quirksMap             map[string]string
	copyQuirks            []string
	requireLock           bool
	requestPath           string
	pt                    PathType
}

// GetRequestData needed for a Vault request. Only those fields provided by
// GetWriteFields() will be included in the request data.
func (c *contextFuncConfig) IDField() (string, error) {
	if c.IsPathTypeMethod() {
		return consts.FieldMethodID, nil
	} else if c.IsPathTypeName() {
		return consts.FieldName, nil
	}

	return "", fmt.Errorf("unsupported path type %s", c.pt)
}

func (c *contextFuncConfig) PathType() PathType {
	return c.pt
}

// Lock locks the configuration's mutex if locking is required.
// Useful when you want to serialize the CRUD operations for a given method
// resource type. Configurations having the same method type should be
// avoided.
func (c *contextFuncConfig) Lock() {
	if c.requireLock {
		c.mu.Lock()
	}
}

// Unlock unlocks the configuration's mutex if locking is required.
// Useful when you want to serialize the CRUD operations for a given method
// resource type. Configurations having the same method type should be
// avoided.
func (c *contextFuncConfig) Unlock() {
	if c.requireLock {
		c.mu.Unlock()
	}
}

// HasSchema returns true if the schema map contains the provided field.
func (c *contextFuncConfig) HasSchema(k string) bool {
	if c.m == nil {
		return false
	}

	_, ok := c.m[k]
	return ok
}

// GetWriteFields returns non-computed fields that will be included
// in a Vault write request.
func (c *contextFuncConfig) GetWriteFields() []string {
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

// GetSecretFields returns a slice of fields that are
// used to bootstrap a Vault configuration, and whose values can never be
// requested from Vault.
func (c *contextFuncConfig) GetSecretFields() []string {
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

// GetRequestData needed for a Vault request. Only those fields provided by
// GetWriteFields() will be included in the request data.
func (c *contextFuncConfig) GetRequestData(d *schema.ResourceData) map[string]interface{} {
	result := make(map[string]interface{})
	for _, k := range c.GetWriteFields() {
		getter := c.getAPIValueGetter(k)
		if getter == nil {
			getter = c.defaultAPIValueGetter
		}
		if v, ok := getter(d, k); ok {
			result[k] = v
		}
	}
	return result
}

func (c *contextFuncConfig) Method() string {
	return c.method
}

// GetRemappedField returns the remapped key and true if the input field should
// be remapped. This can be useful in the case where private Terraform fields
// collide with those returned from the Vault API.
func (c *contextFuncConfig) GetRemappedField(k string) (string, bool) {
	if c.quirksMap != nil {
		if o, ok := c.quirksMap[k]; ok {
			return o, true
		}
	}
	return k, false
}

// GetCopyQuirks is the slice of schema fields that have values that can be
// copied from the state when the field is not present in the response
// from vault (on read). Setting these fields is only every useful to work around
// bugs in the Vault API.
func (c *contextFuncConfig) GetCopyQuirks() []string {
	return c.copyQuirks
}

func (c *contextFuncConfig) IsPathTypeMethod() bool {
	return c.pt == PathTypeMethodID
}

func (c *contextFuncConfig) IsPathTypeName() bool {
	return c.pt == PathTypeName
}

func (c *contextFuncConfig) IsIDFromResponse() bool {
	if c.pt == PathTypeMethodID {
		return true
	}
	return false
}

func (c *contextFuncConfig) GetRequestPathWithID(id string) (string, error) {
	base, err := c.GetRequestPathBase()
	if err != nil {
		return "", err
	}

	return joinPath(base, id), nil
}

func (c *contextFuncConfig) GetRequestPathBase() (string, error) {
	if c.IsPathTypeMethod() {
		return getMethodRequestPath(c.Method()), nil
	} else if c.IsPathTypeName() {
		return getRequestPath(c.Method()), nil
	}

	return "", fmt.Errorf("no request path method for type %s", c.pt)
}

func (c *contextFuncConfig) GetIDFromResponse(resp *api.Secret) (string, error) {
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

func (c *contextFuncConfig) GetIDFromResourceData(d *schema.ResourceData) (string, error) {
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

func (c *contextFuncConfig) setAPIValueGetter(k string, getterFunc util.VaultAPIValueGetter) {
	if c.apiValueGetters == nil {
		c.apiValueGetters = make(map[string]util.VaultAPIValueGetter)
	}
	c.apiValueGetters[k] = getterFunc
}

func (c *contextFuncConfig) getAPIValueGetter(k string) util.VaultAPIValueGetter {
	if c.apiValueGetters == nil {
		return nil
	}
	return c.apiValueGetters[k]
}

func (c *contextFuncConfig) id(f string, v interface{}) (string, error) {
	id, ok := v.(string)
	if !ok || id == "" {
		return "", fmt.Errorf("value for %q must be non-empty string", f)
	}
	return id, nil
}

// NewContextFuncConfig setups a contextFuncConfig that is supported by any of any Get*ContextFunc factory functions.
func NewContextFuncConfig(method string, pt PathType, m map[string]*schema.Schema,
	computedOnly []string, quirksMap map[string]string, defaultAPIValueGetter util.VaultAPIValueGetter,
) (*contextFuncConfig, error) {
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

	if defaultAPIValueGetter == nil {
		defaultAPIValueGetter = util.GetAPIRequestValueOk
	}

	config := &contextFuncConfig{
		method:                method,
		pt:                    pt,
		m:                     m,
		computedOnly:          computedOnly,
		quirksMap:             quirksMap,
		requireLock:           true,
		defaultAPIValueGetter: defaultAPIValueGetter,
	}

	return config, nil
}

func getMethodSchemaResource(s map[string]*schema.Schema, config *contextFuncConfig) *schema.Resource {
	return getSchemaResource(s, config, mustAddCommonSchema, mustAddCommonMFASchema)
}

func getSchemaResource(s map[string]*schema.Schema, config *contextFuncConfig, addFuncs ...addSchemaFunc) *schema.Resource {
	m := map[string]*schema.Schema{}
	for k, v := range s {
		m[k] = v
	}

	r := &schema.Resource{
		Schema:        m,
		CreateContext: NewCreateContextFunc(config),
		UpdateContext: NewUpdateContextFunc(config),
		ReadContext:   NewReadContextFunc(config),
		DeleteContext: NewDeleteContextFunc(config),
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

	for k, s := range m {
		if s.Computed {
			continue
		}
		switch s.Type {
		case schema.TypeInt, schema.TypeBool:
			if f := config.getAPIValueGetter(k); f == nil {
				config.setAPIValueGetter(k, util.GetAPIRequestValueOkExists)
			}
		}
	}
	config.m = r.Schema

	return r
}

// NewCreateContextFunc for a contextFuncConfig.
// The return function supports the path types: PathTypeName, and PathTypeMethodID
func NewCreateContextFunc(config *contextFuncConfig) schema.CreateContextFunc {
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

		return NewReadContextFunc(config)(ctx, d, meta)
	}
}

// NewUpdateContextFunc for a contextFuncConfig.
// The return function supports the path types: PathTypeName, and PathTypeMethodID
func NewUpdateContextFunc(config *contextFuncConfig) schema.UpdateContextFunc {
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

		// login MFA does not support partial updates unfortunately;
		// so update() becomes very similar to create.
		if _, err := c.Logical().Write(path, config.GetRequestData(d)); err != nil {
			return diag.FromErr(err)
		}

		return NewReadContextFunc(config)(ctx, d, meta)
	}
}

// NewReadContextFunc for a contextFuncConfig.
// The return function supports the path types: PathTypeName, and PathTypeMethodID
func NewReadContextFunc(config *contextFuncConfig) schema.ReadContextFunc {
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
				log.Printf("[WARN] Unsupported response field %q, skipping it", k)
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

		for _, k := range config.GetCopyQuirks() {
			if _, ok := resp.Data[k]; !ok {
				if err := d.Set(k, d.Get(k)); err != nil {
					return diag.FromErr(err)
				}
			}
		}

		// the method_id is renamed to `id` after create,
		// but we want to preserve it as an exportable resource attribute.
		if config.IsPathTypeMethod() {
			k := consts.FieldMethodID
			if _, ok := resp.Data[k]; !ok && config.HasSchema(k) {
				if err := d.Set(k, id); err != nil {
					return diag.FromErr(err)
				}
			}
		}

		return nil
	}
}

// NewDeleteContextFunc for a contextFuncConfig.
// The return function supports the path types: PathTypeName, and PathTypeMethodID
func NewDeleteContextFunc(config *contextFuncConfig) schema.DeleteContextFunc {
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
