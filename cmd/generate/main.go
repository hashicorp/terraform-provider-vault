package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/terraform-providers/terraform-provider-vault/codegen"
)

var pathToOpenAPIDoc = flag.String("openapi-doc", "", "path/to/openapi.json")

func main() {
	logger := hclog.Default()
	flag.Parse()
	if pathToOpenAPIDoc == nil || *pathToOpenAPIDoc == "" {
		logger.Info("'openapi-doc' is required")
		os.Exit(1)
	}
	doc, err := ioutil.ReadFile(*pathToOpenAPIDoc)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	// Read in Vault's description of all the supported endpoints, their methods, and more.
	oasDoc := &framework.OASDocument{}
	if err := json.NewDecoder(bytes.NewBuffer(doc)).Decode(oasDoc); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	count := 0
	for path, pathItem := range oasDoc.Paths {
		for allowedPath, fileType := range codegen.AllowedPaths {
			if !strings.HasPrefix(path, allowedPath) {
				continue
			}
			logger.Info(fmt.Sprintf("generating %s and docs for %s\n", fileType.String(), path))
			if err := codegen.GenerateFiles(logger, fileType, path, pathItem); err != nil {
				if err == codegen.ErrUnsupported {
					logger.Warn(fmt.Sprintf("couldn't generate %s, continuing", path))
					continue
				}
				logger.Error(err.Error())
				os.Exit(1)
			}
			count += 2
		}
	}
	logger.Info(fmt.Sprintf("generated %d files\n", count))
}
