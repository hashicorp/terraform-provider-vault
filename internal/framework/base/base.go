package base

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

type withMeta struct {
	meta *provider.ProviderMeta
}

func (w *withMeta) Meta() *provider.ProviderMeta {
	return w.meta
}

// ResourceWithConfigure is a structure to be embedded within a Resource that
// implements the ResourceWithConfigure interface.
type ResourceWithConfigure struct {
	withMeta
}

// Configure enables provider-level data or clients to be set in the
// provider-defined Resource type.
func (r *ResourceWithConfigure) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	if v, ok := request.ProviderData.(*provider.ProviderMeta); ok {
		r.meta = v
	}
}

// WithImportByID is intended to be embedded in resources which import state
// via the "id" attribute.
//
// https://developer.hashicorp.com/terraform/plugin/framework/resources/import.
//
// This will ensure the Vault namespace is written to state if it is set in the
// environment.
// https://registry.terraform.io/providers/hashicorp/vault/latest/docs#namespace-support
type WithImportByID struct{}

func (w *WithImportByID) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root(consts.FieldID), request, response)

	ns := os.Getenv(consts.EnvVarVaultNamespaceImport)
	if ns != "" {
		tflog.Info(
			ctx,
			fmt.Sprintf("Environment variable %s set, attempting TF state import", consts.EnvVarVaultNamespaceImport),
			map[string]any{consts.FieldNamespace: ns},
		)
		response.Diagnostics.Append(
			response.State.SetAttribute(ctx, path.Root(consts.FieldNamespace), ns)...,
		)
	}
}

// DataSourceWithConfigure is a structure to be embedded within a DataSource
// that implements the DataSourceWithConfigure interface.
type DataSourceWithConfigure struct {
	withMeta
}

// Configure enables provider-level data or clients to be set in the
// provider-defined DataSource type.
func (d *DataSourceWithConfigure) Configure(_ context.Context, request datasource.ConfigureRequest, response *datasource.ConfigureResponse) {
	if v, ok := request.ProviderData.(*provider.ProviderMeta); ok {
		d.meta = v
	}
}

// EphemeralResourceWithConfigure is a structure to be embedded within an Ephemeral Resource that
// implements the EphemeralResource with Configure interface.
type EphemeralResourceWithConfigure struct {
	withMeta
}

// Configure enables provider-level data or clients to be set in the
// provider-defined DataSource type.
func (r *EphemeralResourceWithConfigure) Configure(_ context.Context, request ephemeral.ConfigureRequest, response *ephemeral.ConfigureResponse) {
	if v, ok := request.ProviderData.(*provider.ProviderMeta); ok {
		r.meta = v
	}
}
