package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io/ioutil"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-provider-vault/codegen"
	"github.com/hashicorp/vault/sdk/framework"
)

var pathToOpenAPIDoc = flag.String("openapi-doc", "", "path/to/openapi.json")

func main() {
	logger := hclog.Default()
	flag.Parse()
	if pathToOpenAPIDoc == nil || *pathToOpenAPIDoc == "" {
		logger.Error("'openapi-doc' is required")
		os.Exit(1)
	}
	doc, err := ioutil.ReadFile(*pathToOpenAPIDoc)
	if err != nil {
		logger.Error("Unable to read file [%s]: %s", *pathToOpenAPIDoc, err.Error())
		os.Exit(1)
	}

	// Read in Vault's description of all the supported endpoints, their methods, and more.
	oasDoc := &framework.OASDocument{}
	if err := json.NewDecoder(bytes.NewBuffer(doc)).Decode(oasDoc); err != nil {
		logger.Error("Failed to decode JSON from file [%s]: %s", *pathToOpenAPIDoc, err.Error())
		os.Exit(1)
	}

	if err := codegen.Run(logger, oasDoc.Paths); err != nil {
		logger.Error("Failed to generate code: %s", err.Error())
		os.Exit(1)
	}
}
