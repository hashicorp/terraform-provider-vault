package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"sort"

	"github.com/hashicorp/vault/logical/framework"
	"github.com/terraform-providers/terraform-provider-vault/vault"
)

var pathToOpenAPIDoc = flag.String("openapi-doc", "", "path/to/openapi.json")

// This tool is used for generating a coverage report regarding
// how much of the Vault API can be consumed with the Terraform
// Vault provider.
func main() {
	flag.Parse()
	if pathToOpenAPIDoc == nil || *pathToOpenAPIDoc == "" {
		fmt.Println("'openapi-doc' is required")
		os.Exit(1)
	}
	doc, err := ioutil.ReadFile(*pathToOpenAPIDoc)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// Read in Vault's description of all the supported endpoints, their methods, and more.
	oasDoc := &framework.OASDocument{}
	if err := json.NewDecoder(bytes.NewBuffer(doc)).Decode(oasDoc); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// Gather up all the paths/endpoints available in Vault, and have a bool to represent
	// whether they've been "seen" yet in this provider.
	vaultPaths := make(map[string]bool)
	for path := range oasDoc.Paths {
		vaultPaths[path] = false
	}

	// Go through the registries and mark the paths/endpoints they support,
	// remarking upon notable observations along the way.
	for _, registry := range []map[string]*vault.Description{vault.DataSourceRegistry, vault.ResourceRegistry} {
		for _, desc := range registry {
			for _, path := range desc.PathInventory {
				if path == vault.GenericPath || path == vault.UnknownPath {
					continue
				}
				seenBefore, isCurrentlyInVault := vaultPaths[path]
				if !isCurrentlyInVault && !desc.EnterpriseOnly {
					fmt.Println(path + " is not currently in Vault")
				}
				if seenBefore {
					fmt.Println(path + " is in the Terraform Vault Provider multiple times")
				}
				vaultPaths[path] = true
			}
		}
	}

	// Separate what's supported from what isn't to make our report more readable.
	supportedVaultEndpoints := []string{}
	unSupportedVaultEndpoints := []string{}
	for path, seen := range vaultPaths {
		if seen {
			supportedVaultEndpoints = append(supportedVaultEndpoints, path)
		} else {
			unSupportedVaultEndpoints = append(unSupportedVaultEndpoints, path)
		}
	}

	// Surely this output could be done more gracefully with a template,
	// but this is quick and very easy to edit or maintain.
	fmt.Println(" ")
	fmt.Printf("%.0f percent coverage\n", float64(len(supportedVaultEndpoints))/float64(len(vaultPaths))*100)
	fmt.Printf("%d of %d vault paths are supported\n", len(supportedVaultEndpoints), len(vaultPaths))
	fmt.Printf("%d of %d vault paths are unsupported\n", len(unSupportedVaultEndpoints), len(vaultPaths))

	fmt.Println(" ")
	fmt.Println("SUPPORTED")
	sort.Strings(supportedVaultEndpoints)
	for _, path := range supportedVaultEndpoints {
		fmt.Println("    " + path)
	}

	fmt.Println(" ")
	fmt.Println("UNSUPPORTED")
	sort.Strings(unSupportedVaultEndpoints)
	for _, path := range unSupportedVaultEndpoints {
		fmt.Println("    " + path)
	}
}
