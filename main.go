// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5/tf5server"
	"github.com/hashicorp/terraform-plugin-mux/tf5muxserver"
	"github.com/hashicorp/terraform-provider-vault/schema"
	"github.com/hashicorp/terraform-provider-vault/vault"
)

func main() {
	ctx := context.Background()

	sdkv2Provider := schema.NewProvider(vault.Provider())

	providers := []func() tfprotov5.ProviderServer{
		// providerserver.NewProtocol5(provider.New()), // Example terraform-plugin-framework provider
		sdkv2Provider.GRPCProvider,
	}

	muxServer, err := tf5muxserver.NewMuxServer(ctx, providers...)
	if err != nil {
		log.Fatal(err)
	}

	var serveOpts []tf5server.ServeOpt

	var debug bool
	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()
	if debug {
		serveOpts = append(serveOpts, tf5server.WithManagedDebug())
	}

	err = tf5server.Serve(
		"registry.terraform.io/hashicorp/vault",
		muxServer.ProviderServer,
		serveOpts...,
	)

	if err != nil {
		log.Fatal(err)
	}

	// fix duplicate timestamp and incorrect level messages for legacy sdk v2
	// https://developer.hashicorp.com/terraform/plugin/log/writing#legacy-log-troubleshooting
	log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
}
