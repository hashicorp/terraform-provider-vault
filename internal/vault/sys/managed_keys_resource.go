// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"reflect"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/base"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/client"
	"github.com/hashicorp/terraform-provider-vault/internal/framework/errutil"
	"github.com/hashicorp/vault/api"
)

const (
	kmsTypePKCS  = "pkcs11"
	kmsTypeAWS   = "awskms"
	kmsTypeAzure = "azurekeyvault"
)

// Ensure the implementation satisfies the resource.ResourceWithConfigure interface
var _ resource.ResourceWithConfigure = &ManagedKeysResource{}

// NewManagedKeysResource returns the implementation for the managed_keys resource
func NewManagedKeysResource() resource.Resource { return &ManagedKeysResource{} }

// ManagedKeysResource implements the resource
type ManagedKeysResource struct {
	base.ResourceWithConfigure
	base.WithImportByID
}

type ManagedKeysModel struct {
	base.BaseModelLegacy

	AWS   types.List `tfsdk:"aws"`
	Azure types.List `tfsdk:"azure"`
	PKCS  types.List `tfsdk:"pkcs"`
}

func (m *ManagedKeysModel) AsMap() map[string]types.List {
	return map[string]types.List{
		kmsTypeAWS:   m.AWS,
		kmsTypeAzure: m.Azure,
		kmsTypePKCS:  m.PKCS,
	}
}

type ManagedKeyEntryCommon struct {
	AllowGenerateKey types.Bool   `tfsdk:"allow_generate_key"`
	AllowReplaceKey  types.Bool   `tfsdk:"allow_replace_key"`
	AllowStoreKey    types.Bool   `tfsdk:"allow_store_key"`
	AnyMount         types.Bool   `tfsdk:"any_mount"`
	UUID             types.String `tfsdk:"uuid"`
}

type ManagedKeyEntryCommonAPIModel struct {
	AllowGenerateKey bool   `json:"allow_generate_key"`
	AllowReplaceKey  bool   `json:"allow_replace_key"`
	AllowStoreKey    bool   `json:"allow_store_key"`
	AnyMount         bool   `json:"any_mount"`
	UUID             string `json:"uuid"`
}

type ManagedKeyEntryAWS struct {
	ManagedKeyEntryCommon
	Name      types.String `tfsdk:"name"`
	AccessKey types.String `tfsdk:"access_key"`
	SecretKey types.String `tfsdk:"secret_key"`
	Curve     types.String `tfsdk:"curve"`
	Endpoint  types.String `tfsdk:"endpoint"`
	KeyBits   types.String `tfsdk:"key_bits"`
	KeyType   types.String `tfsdk:"key_type"`
	KMSKey    types.String `tfsdk:"kms_key"`
	Region    types.String `tfsdk:"region"`
}

type ManagedKeyEntryAWSAPIModel struct {
	ManagedKeyEntryCommonAPIModel
	Name      string `json:"name"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
	Curve     string `json:"curve"`
	Endpoint  string `json:"endpoint"`
	KeyBits   string `json:"key_bits"`
	KeyType   string `json:"key_type"`
	KMSKey    string `json:"kms_key"`
	Region    string `json:"region"`
}

type ManagedKeyEntryPKCS struct {
	ManagedKeyEntryCommon
	Name           types.String `tfsdk:"name"`
	Library        types.String `tfsdk:"library"`
	KeyLabel       types.String `tfsdk:"key_label"`
	KeyID          types.String `tfsdk:"key_id"`
	Mechanism      types.String `tfsdk:"mechanism"`
	Pin            types.String `tfsdk:"pin"`
	Slot           types.String `tfsdk:"slot"`
	TokenLabel     types.String `tfsdk:"token_label"`
	Curve          types.String `tfsdk:"curve"`
	ForceRwSession types.String `tfsdk:"force_rw_session"`
	KeyBits        types.String `tfsdk:"key_bits"`
}

type ManagedKeyEntryPKCSAPIModel struct {
	ManagedKeyEntryCommonAPIModel
	Name           string  `json:"name"`
	Library        string  `json:"library"`
	KeyLabel       string  `json:"key_label"`
	KeyID          string  `json:"key_id"`
	Mechanism      string  `json:"mechanism"`
	Pin            string  `json:"pin"`
	Slot           *string `json:"slot"`
	TokenLabel     *string `json:"token_label"`
	Curve          *string `json:"curve"`
	ForceRwSession *string `json:"force_rw_session"`
	KeyBits        *string `json:"key_bits"`
}

type ManagedKeyEntryAzure struct {
	ManagedKeyEntryCommon
	Name         types.String `tfsdk:"name"`
	TenantID     types.String `tfsdk:"tenant_id"`
	ClientID     types.String `tfsdk:"client_id"`
	ClientSecret types.String `tfsdk:"client_secret"`
	Environment  types.String `tfsdk:"environment"`
	VaultName    types.String `tfsdk:"vault_name"`
	KeyName      types.String `tfsdk:"key_name"`
	Resource     types.String `tfsdk:"resource"`
	KeyBits      types.String `tfsdk:"key_bits"`
	KeyType      types.String `tfsdk:"key_type"`
}

type ManagedKeyEntryAzureAPIModel struct {
	ManagedKeyEntryCommonAPIModel
	Name         string `json:"name"`
	TenantID     string `json:"tenant_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Environment  string `json:"environment"`
	VaultName    string `json:"vault_name"`
	KeyName      string `json:"key_name"`
	Resource     string `json:"resource"`
	KeyBits      string `json:"key_bits"`
	KeyType      string `json:"key_type"`
}

/*
func apiModelToModel[A, M any](a A) (*M, error) {
	// First turn the api model into a temporary map t via json
	j, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	t := map[string]any{}
	err = json.Unmarshal(j, &t)
	if err != nil {
		return nil, err
	}

	// Now change the values of t to hold the same types as the model object fields
	for k, v := range t {
		switch x := v.(type) {
		case *string:
			t[k] = types.StringPointerValue(x)
		case string:
			t[k] = types.StringValue(x)
		case *bool:
			t[k] = types.BoolPointerValue(x)
		case bool:
			t[k] = types.BoolValue(x)
		default:
			return nil, fmt.Errorf("unknown type %T", x)
		}
	}
	var m M
	cfg1, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName: "tfsdk",
		Result:  &m,
		Squash:  true,
	})
	if err != nil {
		return nil, err
	}
	if err := cfg1.Decode(t); err != nil {
		return nil, err
	}
	return &m, nil
}
*/

// apiModelToModel populates m based on a.  Both are expected to be structs that
// have the same keys in the same order, but while a has regular Go types like
// string or *string, m has tf types like StringValue.
func apiModelToModel(a, m any) error {
	return apiModelToModelValues(reflect.ValueOf(a), reflect.ValueOf(m).Elem())
}

func apiModelToModelValues(aVal, mVal reflect.Value) error {
	aType := aVal.Type()
	mType := mVal.Type()

	if aType.NumField() != mType.NumField() {
		return fmt.Errorf("field count mismatch")
	}
	for i := 0; i < aVal.NumField(); i++ {
		aT := aType.Field(i)
		aF := aVal.Field(i)
		mF := mVal.Field(i)
		switch aF.Kind() {
		case reflect.Struct:
			if err := apiModelToModelValues(aF, mF); err != nil {
				return err
			}
		case reflect.Bool:
			mF.Set(reflect.ValueOf(types.BoolValue(aF.Bool())))
		case reflect.String:
			mF.Set(reflect.ValueOf(types.StringValue(aF.String())))
		case reflect.Pointer:
			e := aF.Elem()
			switch aT.Type.Elem().Kind() {
			case reflect.String:
				if aF.IsNil() {
					mF.Set(reflect.ValueOf(types.StringPointerValue(nil)))
				} else {
					mF.Set(reflect.ValueOf(types.StringValue(e.String())))
				}
			case reflect.Bool:
				if aF.IsNil() {
					mF.Set(reflect.ValueOf(types.BoolPointerValue(nil)))
				} else {
					mF.Set(reflect.ValueOf(types.BoolValue(e.Bool())))
				}
			default:
				return fmt.Errorf("unknown pointer type %T of kind %v on field %s", aF, e.Kind(), aType.Field(i).Name)
			}
		default:
			return fmt.Errorf("unknown type %T on field %s", aF, aType.Field(i).Name)
		}
	}
	return nil
}

func getManagedKeysPathPrefix(keyType string) string {
	return fmt.Sprintf("sys/managed-keys/%s", keyType)
}

func getManagedKeysPath(keyType, name string) string {
	return fmt.Sprintf("%s/%s", getManagedKeysPathPrefix(keyType), name)
}

func isUnsupportedKeyTypeError(err error) bool {
	return strings.Contains(err.Error(), "unsupported managed key type")
}

type managedKeysConfig struct {
	providerType string
	keyType      string
	attributes   func() map[string]schema.Attribute
	redacted     []string
}

var (
	managedKeysAWSConfig = &managedKeysConfig{
		providerType: consts.FieldAWS,
		keyType:      kmsTypeAWS,
		attributes:   managedKeysAWSConfigAttributes,
		redacted:     []string{consts.FieldAccessKey, consts.FieldSecretKey},
	}

	managedKeysAzureConfig = &managedKeysConfig{
		providerType: consts.FieldAzure,
		keyType:      kmsTypeAzure,
		attributes:   managedKeysAzureConfigAttributes,
	}

	managedKeysPKCSConfig = &managedKeysConfig{
		providerType: consts.FieldPKCS,
		keyType:      kmsTypePKCS,
		attributes:   managedKeysPKCSConfigAttributes,
		redacted:     []string{consts.FieldPin, consts.FieldKeyID},
	}

	managedKeyProviders = []*managedKeysConfig{
		managedKeysAWSConfig,
		managedKeysAzureConfig,
		managedKeysPKCSConfig,
	}
)

func getManagedKeyConfig(providerType string) (*managedKeysConfig, error) {
	for _, config := range managedKeyProviders {
		if config.providerType == providerType {
			return config, nil
		}
	}

	return nil, fmt.Errorf("invalid provider type %s", providerType)
}

func commonManagedKeysAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		consts.FieldAllowGenerateKey: schema.BoolAttribute{
			Optional: true,
			Computed: true,
			Description: "If no existing key can be found in the referenced " +
				"backend, instructs Vault to generate a key within the backend",
		},

		consts.FieldAllowReplaceKey: schema.BoolAttribute{
			Optional: true,
			Computed: true,
			Description: "Controls the ability for Vault to replace through " +
				"generation or importing a key into the configured backend even " +
				"if a key is present, if set to false those operations are forbidden " +
				"if a key exists.",
		},

		consts.FieldAllowStoreKey: schema.BoolAttribute{
			Optional: true,
			Computed: true,
			Description: "Controls the ability for Vault to import a key to the " +
				"configured backend, if 'false', those operations will be forbidden",
		},

		consts.FieldAnyMount: schema.BoolAttribute{
			Optional:    true,
			Computed:    true,
			Description: "Allow usage from any mount point within the namespace if 'true'",
		},

		consts.FieldUUID: schema.StringAttribute{
			Computed:    true,
			Description: "ID of the managed key read from Vault",
		},
	}
}

func attrsToTypes(m map[string]schema.Attribute) map[string]attr.Type {
	ret := map[string]attr.Type{}
	for k, v := range m {
		ret[k] = v.GetType()
	}
	return ret
}

func managedKeysAWSConfigAttributes() map[string]schema.Attribute {
	ret := map[string]schema.Attribute{
		"name":       schema.StringAttribute{Required: true},
		"access_key": schema.StringAttribute{Optional: true, Sensitive: true},
		"secret_key": schema.StringAttribute{Optional: true, Sensitive: true},
		"curve":      schema.StringAttribute{Optional: true},
		"endpoint":   schema.StringAttribute{Optional: true},
		"key_bits":   schema.StringAttribute{Optional: true},
		"key_type":   schema.StringAttribute{Required: true},
		"kms_key":    schema.StringAttribute{Required: true},
		"region":     schema.StringAttribute{Optional: true, Computed: true},
	}

	maps.Insert(ret, maps.All(commonManagedKeysAttributes()))

	return ret
}

func managedKeysAzureConfigAttributes() map[string]schema.Attribute {
	ret := map[string]schema.Attribute{
		"name":          schema.StringAttribute{Required: true},
		"tenant_id":     schema.StringAttribute{Required: true},
		"client_id":     schema.StringAttribute{Required: true},
		"client_secret": schema.StringAttribute{Required: true, Sensitive: true},
		"environment":   schema.StringAttribute{Optional: true, Computed: true},
		"vault_name":    schema.StringAttribute{Required: true},
		"key_name":      schema.StringAttribute{Required: true},
		"resource":      schema.StringAttribute{Optional: true, Computed: true},
		"key_bits":      schema.StringAttribute{Optional: true},
		"key_type":      schema.StringAttribute{Required: true},
	}

	maps.Insert(ret, maps.All(commonManagedKeysAttributes()))

	return ret
}

func managedKeysPKCSConfigAttributes() map[string]schema.Attribute {
	ret := map[string]schema.Attribute{
		"name":    schema.StringAttribute{Required: true},
		"library": schema.StringAttribute{Required: true},
		"key_label": schema.StringAttribute{Optional: true,
			Validators: []validator.String{stringvalidator.AtLeastOneOf(
				path.MatchRelative().AtParent().AtName("key_id"),
			)},
		},
		"key_id":           schema.StringAttribute{Optional: true, Computed: true, Sensitive: true},
		"mechanism":        schema.StringAttribute{Required: true},
		"pin":              schema.StringAttribute{Required: true, Sensitive: true},
		"slot":             schema.StringAttribute{Optional: true},
		"token_label":      schema.StringAttribute{Optional: true},
		"curve":            schema.StringAttribute{Optional: true},
		"key_bits":         schema.StringAttribute{Optional: true},
		"force_rw_session": schema.StringAttribute{Optional: true},
	}

	maps.Insert(ret, maps.All(commonManagedKeysAttributes()))

	return ret
}

// Metadata sets the resource type name
func (r *ManagedKeysResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_managed_keys"
}

// Schema defines the resource schema using nested blocks for aws/azure/pkcs
func (r *ManagedKeysResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: make(map[string]schema.Attribute),
		Blocks: map[string]schema.Block{
			"aws": schema.ListNestedBlock{
				NestedObject: schema.NestedBlockObject{Attributes: managedKeysAWSConfigAttributes()},
			},
			"azure": schema.ListNestedBlock{
				NestedObject: schema.NestedBlockObject{Attributes: managedKeysAzureConfigAttributes()},
			},
			"pkcs": schema.ListNestedBlock{
				NestedObject: schema.NestedBlockObject{Attributes: managedKeysPKCSConfigAttributes()},
			},
		},
		MarkdownDescription: "Provides a resource to manage Managed Keys.",
	}
	base.MustAddLegacyBaseSchema(&resp.Schema)
}

// helper: build map[string]interface{} for a nested block object
func buildMapFromAttrList(ctx context.Context, list types.List) ([]map[string]any, diag.Diagnostics) {
	if list.IsNull() || list.IsUnknown() {
		return nil, nil
	}

	var d diag.Diagnostics

	var elems []map[string]any
	for _, elem := range list.Elements() {
		m, dd := buildMapFromAttrValue(ctx, elem)
		d.Append(dd...)
		if m != nil {
			elems = append(elems, m)
		}
	}
	if d.HasError() {
		return nil, d
	}

	return elems, nil
}

func buildMapFromAttrValue(ctx context.Context, value attr.Value) (map[string]any, diag.Diagnostics) {
	var d diag.Diagnostics

	ret := map[string]any{}
	v, err := value.ToTerraformValue(ctx)
	if err != nil {
		d.AddError(errutil.ClientConfigureErr(err))
		return nil, d
	}
	e := map[string]tftypes.Value{}
	if err := v.As(&e); err != nil {
		d.AddError(errutil.ClientConfigureErr(err))
		return nil, d
	}
	for k, v := range e {
		if v.IsNull() {
			// TODO do we always want to ignore null values?  What about unsetting an existing value?
			continue
		}
		if v.IsKnown() {
			switch {
			case v.Type().Is(tftypes.String):
				var s string
				if err := v.As(&s); err != nil {
					d.AddError(errutil.ClientConfigureErr(err))
					return nil, d
				}
				ret[k] = s
			case v.Type().Is(tftypes.Bool):
				var b bool
				if err := v.As(&b); err != nil {
					d.AddError(errutil.ClientConfigureErr(err))
					return nil, d
				}
				ret[k] = b
			default:
				d.AddError("unknown type when building attr map", v.Type().String())
				return nil, d
			}
		}
	}
	return ret, d
}

// TODO MountCreateContextWrapper 1.10
func (r *ManagedKeysResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	resp.Diagnostics = r.createUpdate(ctx, &req.Plan, &resp.State)
}

func (r *ManagedKeysResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	oldData, newData := &ManagedKeysModel{}, &ManagedKeysModel{}
	resp.Diagnostics.Append(req.State.Get(ctx, oldData)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(req.Plan.Get(ctx, newData)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), newData.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// Delete all the old keys that don't exist in the new planned state
	for keyType, oldList := range oldData.AsMap() {
		entries, d := buildMapFromAttrList(ctx, oldList)
		resp.Diagnostics.Append(d...)
		if d.HasError() {
			return
		}
		toDelete := map[string]struct{}{}
		for _, e := range entries {
			toDelete[e[consts.FieldName].(string)] = struct{}{}
		}

		entries, d = buildMapFromAttrList(ctx, newData.AsMap()[keyType])
		resp.Diagnostics.Append(d...)
		if d.HasError() {
			return
		}
		for _, e := range entries {
			delete(toDelete, e[consts.FieldName].(string))
		}

		for name := range toDelete {
			_, err := cli.Logical().DeleteWithContext(ctx, getManagedKeysPath(keyType, name))
			if err != nil {
				resp.Diagnostics.AddError(fmt.Sprintf("error deleting key %q of type %s", name, keyType), err.Error())
				return
			}
		}
	}

	// Now create or update any keys that do belong in the new planned state
	resp.Diagnostics = r.createUpdate(ctx, &req.Plan, &resp.State)
}

func (r *ManagedKeysResource) createUpdate(ctx context.Context, plan *tfsdk.Plan, state *tfsdk.State) (diags diag.Diagnostics) {
	data := &ManagedKeysModel{}
	diags.Append(plan.Get(ctx, data)...)
	if diags.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		diags.AddError(errutil.ClientConfigureErr(err))
		return
	}

	for keyType, list := range data.AsMap() {
		if list.IsNull() {
			continue
		}
		entries, d := buildMapFromAttrList(ctx, list)
		diags.Append(d...)
		if d.HasError() {
			return
		}
		for _, ent := range entries {
			name := ent["name"].(string)
			path := getManagedKeysPath(keyType, name)
			log.Printf("[DEBUG] Writing managed key data to %s", path)
			if _, err := cli.Logical().WriteWithContext(ctx, path, ent); err != nil {
				diags.AddError("Vault write error", err.Error())
				return
			}
		}
	}

	// write ID default for backwards compatibility
	data.ID = types.StringValue("default")
	data, diags = r.read(ctx, data)
	if !diags.HasError() {
		diags.Append(state.Set(ctx, data)...)
	}
	return
}

func (r *ManagedKeysResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var cur ManagedKeysModel
	resp.Diagnostics = req.State.Get(ctx, &cur)
	if resp.Diagnostics.HasError() {
		return
	}
	data, d := r.read(ctx, &cur)
	resp.Diagnostics = d
	resp.Diagnostics.Append(resp.State.Set(ctx, data)...)
}

func (r *ManagedKeysResource) read(ctx context.Context, cur *ManagedKeysModel) (*ManagedKeysModel, diag.Diagnostics) {
	var data ManagedKeysModel
	var diag diag.Diagnostics

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		diag.AddError(errutil.ClientConfigureErr(err))
		return nil, diag
	}

	awsList, d := readManagedKeys[ManagedKeyEntryAWSAPIModel, ManagedKeyEntryAWS](ctx, cur.AWS, cli, consts.FieldAWS)
	diag.Append(d...)
	if !d.HasError() {
		// Convert to types and set on data
		config, err := getManagedKeyConfig(consts.FieldAWS)
		if err != nil {
			d.AddError("error reading managed keys", err.Error())
			return nil, d
		}
		t := types.ObjectType{
			AttrTypes: attrsToTypes(config.attributes()),
		}
		if val, diags := types.ListValueFrom(ctx, t, awsList); diags.HasError() {
			diag.Append(diags...)
		} else {
			data.AWS = val
		}
	}

	pkcsList, d := readManagedKeys[ManagedKeyEntryPKCSAPIModel, ManagedKeyEntryPKCS](ctx, cur.PKCS, cli, consts.FieldPKCS)
	diag.Append(d...)
	if !d.HasError() {
		// Convert to types and set on data
		config, err := getManagedKeyConfig(consts.FieldPKCS)
		if err != nil {
			d.AddError("error reading managed keys", err.Error())
			return nil, d
		}
		t := types.ObjectType{
			AttrTypes: attrsToTypes(config.attributes()),
		}
		if val, diags := types.ListValueFrom(ctx, t, pkcsList); diags.HasError() {
			diag.Append(diags...)
		} else {
			data.PKCS = val
		}
	}

	azureList, d := readManagedKeys[ManagedKeyEntryAzureAPIModel, ManagedKeyEntryAzure](ctx, cur.Azure, cli, consts.FieldAzure)
	diag.Append(d...)
	if !d.HasError() {
		// Convert to types and set on data
		config, err := getManagedKeyConfig(consts.FieldAzure)
		if err != nil {
			d.AddError("error reading managed keys", err.Error())
			return nil, d
		}
		t := types.ObjectType{
			AttrTypes: attrsToTypes(config.attributes()),
		}
		if val, diags := types.ListValueFrom(ctx, t, azureList); diags.HasError() {
			diag.Append(diags...)
		} else {
			data.Azure = val
		}
	}

	data.ID = types.StringValue("default")

	if diag.HasError() {
		return nil, diag
	}
	return &data, nil
}

func handleKeyProviderRequired(providerType string, err error) error {
	isUnsupported := isUnsupportedKeyTypeError(err)
	if isUnsupported {
		return fmt.Errorf("managed key type %s is not supported by this version of Vault, err=%s",
			providerType, err)
	}

	return err
}

func updateRedactedFields(ctx context.Context, cur map[string]any, providerType, name string, fields []string, m map[string]interface{}) diag.Diagnostics {
	for _, field := range fields {
		m[field] = cur[field]

		//ps, diag := state.PathMatches(ctx, path.MatchRoot(providerType).AtName(name).AtName(field))
		//if diag.HasError() {
		//	return diag
		//}
		//if len(ps) != 1 {
		//	diag.AddError("expected single path match", fmt.Sprintf("got %d matches for provider=%s, name=%s, field=%s", len(ps), providerType, name, field))
		//	return diag
		//}
		//var s string
		//if d := state.GetAttribute(ctx, ps[0], &s); d.HasError() {
		//	return d.Errors()
		//} else {
		//	m[field] = s
		//}
	}
	return nil
}

func readManagedKeys[A, M any](ctx context.Context, curList types.List, client *api.Client, providerType string) ([]M, diag.Diagnostics) {
	var d diag.Diagnostics
	config, err := getManagedKeyConfig(providerType)
	if err != nil {
		d.AddError("error reading managed keys", err.Error())
		return nil, d
	}

	p := getManagedKeysPathPrefix(config.keyType)
	log.Printf("[DEBUG] Listing data from Vault at %s", p)
	resp, err := client.Logical().List(p)
	if err != nil {
		if err := handleKeyProviderRequired(providerType, err); err != nil {
			d.AddError("error reading managed keys", err.Error())
			return nil, d
		}
	}

	if resp == nil {
		return nil, nil
	}

	ents, diags := buildMapFromAttrList(ctx, curList)
	if diags.HasError() {
		return nil, diags
	}
	curMap := map[string]map[string]any{}
	for _, ent := range ents {
		curMap[ent[consts.FieldName].(string)] = ent
	}

	var ret []M
	if v, ok := resp.Data["keys"]; ok {
		for _, nameRaw := range v.([]interface{}) {
			name := nameRaw.(string)

			p := getManagedKeysPath(config.keyType, name)
			log.Printf("[DEBUG] Reading from Vault at %s", p)
			resp, err := client.Logical().ReadWithContext(ctx, p)
			if err != nil {
				d.AddError(fmt.Sprintf("error reading managed keys from %s", p), err.Error())
				return nil, d
			}
			if resp == nil {
				continue
			}

			respData := resp.Data

			// set fields from TF config
			// these values are returned as "redacted" from Vault
			cur := curMap[name]
			if cur != nil {
				if d := updateRedactedFields(ctx, cur, providerType, name, config.redacted, respData); d.HasError() {
					return nil, d.Errors()
				}
			}

			var apiModel A

			if rdmr, ok := respData["mechanism"]; ok {
				val := rdmr.(json.Number)
				i, err := val.Int64()
				if err != nil {
					diags.AddError("error parsing mechanism", err.Error())
				} else {
					respData["mechanism"] = fmt.Sprintf("0x%04x", i)
				}
			}
			// Use WeakDecode because we want to coerce numbers into strings
			cfg, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				WeaklyTypedInput: true,
				Squash:           true,
				Result:           &apiModel,
				TagName:          "json",
			})
			if err != nil {
				d.AddError(fmt.Sprintf("error decoding"), err.Error())
				return nil, d
			}
			if err := cfg.Decode(respData); err != nil {
				d.AddError(fmt.Sprintf("error converting managed keys read from %s to api model", p), err.Error())
				return nil, d
			}
			var model M
			if err := apiModelToModel(apiModel, &model); err != nil {
				d.AddError(fmt.Sprintf("error converting managed keys read from %s to model", p), err.Error())
				return nil, d
			} else {
				ret = append(ret, model)
			}
		}
	}

	return ret, nil
}

func (r *ManagedKeysResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	data := &ManagedKeysModel{}
	resp.Diagnostics.Append(req.State.Get(ctx, data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cli, err := client.GetClient(ctx, r.Meta(), data.Namespace.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(errutil.ClientConfigureErr(err))
		return
	}

	// TODO why are we listing?  Why don't we just delete everything in state?
	for keyType, list := range data.AsMap() {
		if list.IsNull() {
			continue
		}
		respList, err := cli.Logical().ListWithContext(ctx, getManagedKeysPathPrefix(keyType))
		if err != nil {
			resp.Diagnostics.AddError("error listing keys of type "+keyType, err.Error())
			return
		}
		if respList == nil {
			continue
		}
		if v, ok := respList.Data["keys"]; ok {
			for _, n := range v.([]interface{}) {
				name := n.(string)
				_, err = cli.Logical().DeleteWithContext(ctx, getManagedKeysPath(keyType, name))
				if err != nil {
					resp.Diagnostics.AddError(fmt.Sprintf("error deleting key %q of type %s", name, keyType), err.Error())
					return
				}
			}
		}
	}

	// TODO we don't actually have to do a read, but maybe we should?
	//data, resp.Diagnostics = r.read(ctx, data)
	//if !resp.Diagnostics.HasError() {
	//	resp.Diagnostics.Append(resp.State.Set(ctx, data)...)
	//}
}
