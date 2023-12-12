package client

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
	"github.com/hashicorp/vault/api"
)

func GetClient(ctx context.Context, meta interface{}, namespace string) (*api.Client, error) {
	var p *provider.ProviderMeta

	switch v := meta.(type) {
	case *provider.ProviderMeta:
		p = v
	default:
		return nil, fmt.Errorf("meta argument must be a %T, not %T", p, meta)
	}

	ns := namespace
	if namespace == "" {
		// in order to import namespaced resources the user must provide
		// the namespace from an environment variable.
		ns = os.Getenv(consts.EnvVarVaultNamespaceImport)
		if ns != "" {
			tflog.Debug(ctx, fmt.Sprintf("Value for %q set from environment", consts.FieldNamespace))
		}
	}

	if ns != "" {
		return p.GetNSClient(ns)
	}

	return p.GetClient()
}
