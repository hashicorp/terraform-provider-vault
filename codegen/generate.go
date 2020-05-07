package codegen

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
)

// generatedDirPerms uses 0775 because it is the same as for
// the "vault" directory, which is at "drwxrwxr-x".
const generatedDirPerms os.FileMode = 0775

var (
	errUnsupported = errors.New("code and doc generation for this item is unsupported")

	// pathToHomeDir yields the path to the terraform-vault-provider
	// home directory on the machine on which it's running.
	// ex. /home/your-name/go/src/github.com/terraform-providers/terraform-provider-vault
	pathToHomeDir = func() string {
		repoName := "terraform-provider-vault"
		wd, _ := os.Getwd()
		pathParts := strings.Split(wd, repoName)
		return pathParts[0] + repoName
	}()
)

func Run(logger hclog.Logger, paths map[string]*framework.OASPathItem) error {
	// Read in the templates we'll be using.
	h, err := newTemplateHandler(logger)
	if err != nil {
		return err
	}
	// Use a file creator so the logger can always be available without having
	// to awkwardly pass it in everywhere.
	fCreator := &fileCreator{
		logger:          logger,
		templateHandler: h,
	}
	createdCount := 0
	for endpoint, templateType := range endpointRegistry {
		logger.Info(fmt.Sprintf("generating %s for %s\n", templateType.String(), endpoint))
		if err := fCreator.GenerateCode(endpoint, paths[endpoint], templateType); err != nil {
			if err == errUnsupported {
				logger.Warn(fmt.Sprintf("couldn't generate %s, continuing", endpoint))
				continue
			}
			logger.Error(err.Error())
			os.Exit(1)
		}
		// TODO in separate PR - add fCreator.GenerateDoc() method
		createdCount++
	}
	logger.Info(fmt.Sprintf("generated %d files\n", createdCount))
	return nil
}

type fileCreator struct {
	logger          hclog.Logger
	templateHandler *templateHandler
}

// GenerateCode is exported because it's the only non-internal method on the fileCreator.
func (c *fileCreator) GenerateCode(endpoint string, endpointInfo *framework.OASPathItem, tmplType templateType) error {
	pathToFile := codeFilePath(tmplType, endpoint)
	return c.writeFile(pathToFile, tmplType, endpoint, endpointInfo)
}

// TODO in a separate PR - add a GenerateDoc method.

func (c *fileCreator) writeFile(pathToFile string, tmplType templateType, endpoint string, endpointInfo *framework.OASPathItem) error {
	parentDir := parentDir(pathToFile)
	wr, closer, err := c.createFileWriter(pathToFile, parentDir)
	if err != nil {
		return err
	}
	defer closer()
	return c.templateHandler.Write(wr, tmplType, parentDir, endpoint, endpointInfo)
}

// createFileWriter creates a file and returns its writer for the caller to use in templating.
// The closer will only be populated if the err is nil.
func (c *fileCreator) createFileWriter(pathToFile, parentDir string) (wr *bufio.Writer, closer func(), err error) {
	var cleanups []func() error
	closer = func() {
		for _, cleanup := range cleanups {
			if err := cleanup(); err != nil {
				c.logger.Error(err.Error())
			}
		}
	}

	// Make the directory and file.
	if err := os.MkdirAll(parentDir, generatedDirPerms); err != nil {
		return nil, nil, err
	}
	f, err := os.Create(pathToFile)
	if err != nil {
		return nil, nil, err
	}
	cleanups = []func() error{
		f.Close,
	}

	// Open the file for writing.
	wr = bufio.NewWriter(f)
	cleanups = []func() error{
		wr.Flush,
		f.Close,
	}
	return wr, closer, nil
}

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
func codeFilePath(tmplType templateType, endpoint string) string {
	filename := fmt.Sprintf("%s%s.go", tmplType.String(), endpoint)
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
func docFilePath(tmplType templateType, endpoint string) string {
	filename := fmt.Sprintf("%s%s.md", tmplType.String(), endpoint)
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

// parentDir returns the directory containing the given file.
// ex. generated/resources/transform-transformation-name.go
// returns generated/resources/
func parentDir(pathToFile string) string {
	lastSlash := strings.LastIndex(pathToFile, "/")
	return pathToFile[:lastSlash]
}
