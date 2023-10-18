// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5/tf5server"
	"github.com/hashicorp/terraform-provider-vault/vault"
)

func main() {
	serverFactory, _, err := vault.ProtoV5ProviderServerFactory(context.Background())
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

	// fix duplicate timestamp and incorrect level messages for legacy sdk v2
	// https://developer.hashicorp.com/terraform/plugin/log/writing#legacy-log-troubleshooting
	log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))

	err = tf5server.Serve(
		"registry.terraform.io/hashicorp/vault",
		serverFactory,
		serveOpts...,
	)

	if err != nil {
		log.Fatal(err)
	}
}
