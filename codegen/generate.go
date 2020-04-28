package codegen

import (
	"fmt"
	"os"
	"strings"
)

// pathToHomeDir yields the path to the terraform-vault-provider
// home directory on the machine on which it's running.
// ex. /home/your-name/go/src/github.com/terraform-providers/terraform-provider-vault
var pathToHomeDir = func() string {
	repoName := "terraform-provider-vault"
	wd, _ := os.Getwd()
	pathParts := strings.Split(wd, repoName)
	return pathParts[0] + repoName
}()

/*
codeFilePath creates a directory structure inside the "generated" folder that's
intended to make it easy to find the file for each endpoint in Vault, even if
we eventually cover all >500 of them and add tests.
	terraform-provider-vault/generated$ tree
	.
	├── datasources
	│   └── transform
	│       ├── decode
	│       │   └── role_name.go
	│       └── encode
	│           └── role_name.go
	└── resources
		└── transform
			├── alphabet
			│   └── name.go
			├── alphabet.go
			├── role
			│   └── name.go
			├── role.go
			├── template
			│   └── name.go
			├── template.go
			├── transformation
			│   └── name.go
			└── transformation.go
*/
func codeFilePath(tmplType templateType, path string) string {
	filename := fmt.Sprintf("%s%s.go", tmplType.String(), path)
	path := filepath.Join(pathToHomeDir, "generated", filename)
	return stripCurlyBraces(path)
}

/*
docFilePath creates a directory structure inside the "website/docs/generated" folder
that's intended to make it easy to find the file for each endpoint in Vault, even if
we eventually cover all >500 of them and add tests.
	terraform-provider-vault/website/docs/generated$ tree
	.
	├── datasources
	│   └── transform
	│       ├── decode
	│       │   └── role_name.md
	│       └── encode
	│           └── role_name.md
	└── resources
		└── transform
			├── alphabet
			│   └── name.md
			├── alphabet.md
			├── role
			│   └── name.md
			├── role.md
			├── template
			│   └── name.md
			├── template.md
			├── transformation
			│   └── name.md
			└── transformation.md
*/
func docFilePath(tmplType templateType, path string) string {
	filename := fmt.Sprintf("%s%s.md", tmplType.String(), path)
	path := filepath.Join(pathToHomeDir, "website", "docs", "generated", filename)
	return stripCurlyBraces(path)
}

// stripCurlyBraces converts a path like
// "generated/resources/transform-transformation-{name}.go"
// to "generated/resources/transform-transformation-name.go".
func stripCurlyBraces(path string) string {
	path = strings.ReplaceAll(path, "{", "")
	path = strings.ReplaceAll(path, "}", "")
	return path
}
