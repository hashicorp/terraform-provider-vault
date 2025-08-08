// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package providertest

import (
	"context"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-provider-vault/vault"
)

// ProtoV5ProviderFactories is a static map containing only the main provider instance
var (
	ProtoV5ProviderFactories map[string]func() (tfprotov5.ProviderServer, error) = protoV5ProviderFactoriesInit(context.Background(), "vault")
)

// testAccProtoV5ProviderFactories will return a map of provider servers
// suitable for use as a resource.TestStep.ProtoV5ProviderFactories.
//
// When multiplexing providers, the schema and configuration handling must
// exactly match between all underlying providers of the mux server. Mismatched
// schemas will result in a runtime error.
// see: https://developer.hashicorp.com/terraform/plugin/framework/migrating/mux
//
// Any tests that use this function will serve as a smoketest to verify the
// provider schemas match 1-1 so that we may catch runtime errors.
func protoV5ProviderFactoriesInit(ctx context.Context, providerNames ...string) map[string]func() (tfprotov5.ProviderServer, error) {
	factories := make(map[string]func() (tfprotov5.ProviderServer, error), len(providerNames))

	for _, name := range providerNames {
		factories[name] = func() (tfprotov5.ProviderServer, error) {
			providerServerFactory, _, err := vault.ProtoV5ProviderServerFactory(ctx)
			if err != nil {
				return nil, err
			}

			return providerServerFactory(), nil
		}
	}

	return factories
}
