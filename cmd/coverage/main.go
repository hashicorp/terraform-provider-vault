package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"sort"

	"github.com/hashicorp/terraform-provider-vault/vault"
	"github.com/hashicorp/vault/sdk/framework"
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
	vaultPaths := map[string]map[string]bool{
		"data source": make(map[string]bool),
		"resource":    make(map[string]bool),
		"all":         make(map[string]bool),
	}
	for path := range oasDoc.Paths {
		vaultPaths["data source"][path] = false
		vaultPaths["resource"][path] = false
		vaultPaths["all"][path] = false
	}

	// Go through the registries and mark the paths/endpoints they support,
	// remarking upon notable observations along the way.
	checkRegistry("data source", vault.DataSourceRegistry, vaultPaths)
	checkRegistry("resource", vault.ResourceRegistry, vaultPaths)

	// Separate what's supported from what isn't to make our report more readable.
	supportedVaultEndpoints := []string{}
	unSupportedVaultEndpoints := []string{}
	for path, seen := range vaultPaths["all"] {
		if seen {
			supportedVaultEndpoints = append(supportedVaultEndpoints, path)
		} else {
			unSupportedVaultEndpoints = append(unSupportedVaultEndpoints, path)
		}
	}

	fmt.Println(" ")
	fmt.Printf("%.0f percent coverage\n", float64(len(supportedVaultEndpoints))/float64(len(vaultPaths["all"]))*100)
	fmt.Printf("%d of %d vault paths are supported\n", len(supportedVaultEndpoints), len(vaultPaths["all"]))
	fmt.Printf("%d of %d vault paths are unsupported\n", len(unSupportedVaultEndpoints), len(vaultPaths["all"]))

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

func checkRegistry(registryType string, registry map[string]*vault.Description, vaultPaths map[string]map[string]bool) {
	for _, desc := range registry {
		for _, path := range desc.PathInventory {
			if path == vault.GenericPath || path == vault.UnknownPath {
				continue
			}
			seenBefore, isCurrentlyInVault := vaultPaths[registryType][path]
			if !isCurrentlyInVault && !desc.EnterpriseOnly {
				fmt.Println(path + " is not currently in Vault")
			}
			if seenBefore {
				fmt.Printf("%s is in the %s registry multiple times\n", path, registryType)
			}
			vaultPaths[registryType][path] = true
			vaultPaths["all"][path] = true
		}
	}
}
