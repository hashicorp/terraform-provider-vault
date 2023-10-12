// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"

	"github.com/hashicorp/terraform-provider-vault/generated"
	"github.com/hashicorp/terraform-provider-vault/schema"
	"github.com/hashicorp/terraform-provider-vault/vault"
)

func main() {
	p := schema.NewProvider(vault.Provider())
	for name, resource := range generated.DataSourceRegistry {
		p.RegisterDataSource(name, vault.UpdateSchemaResource(resource))
	}
	for name, resource := range generated.ResourceRegistry {
		p.RegisterResource(name, vault.UpdateSchemaResource(resource))
	}

	serveOpts := &plugin.ServeOpts{
		ProviderFunc: p.SchemaProvider,
	}

	var debug bool
	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	if debug {
		serveOpts.Debug = debug
		serveOpts.ProviderAddr = "hashicorp/vault"
	}

	// fix duplicate timestamp and incorrect level messages
	// https://developer.hashicorp.com/terraform/plugin/log/writing#legacy-log-troubleshooting
	log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))

	plugin.Serve(serveOpts)
}
