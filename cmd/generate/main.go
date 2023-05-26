// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"flag"
	"os"
)

var pathToOpenAPIDoc = flag.String("openapi-doc", "", "path/to/openapi.json")

func main() {
	// TODO: revisit resource and data generation strategy after v3 release
	os.Stderr.WriteString("resource generation has been disabled, " +
		"please manually update previously generated resources\n")
	os.Exit(1)
}
