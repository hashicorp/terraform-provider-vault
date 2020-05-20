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
	for endpoint, addedInfo := range endpointRegistry {
		logger.Info(fmt.Sprintf("generating %s for %s\n", addedInfo.TemplateType.String(), endpoint))
		if err := fCreator.GenerateCode(endpoint, paths[endpoint], addedInfo); err != nil {
			if err == errUnsupported {
				logger.Warn(fmt.Sprintf("couldn't generate %s, continuing", endpoint))
				continue
			}
			logger.Error(err.Error())
			os.Exit(1)
		}
		logger.Info(fmt.Sprintf("generating %s for %s\n", templateTypeDoc.String(), endpoint))
		if err := fCreator.GenerateDoc(endpoint, paths[endpoint], addedInfo); err != nil {
			logger.Error(err.Error())
			os.Exit(1)
		}
		createdCount += 2
	}
	logger.Info(fmt.Sprintf("generated %d files\n", createdCount))
	return nil
}

type fileCreator struct {
	logger          hclog.Logger
	templateHandler *templateHandler
}

// GenerateCode is exported because it's the only method intended to be used by
// other objects. Unexported methods may be available to other code in this package,
// but they're not intended to be used by anything but the fileCreator.
func (c *fileCreator) GenerateCode(endpoint string, endpointInfo *framework.OASPathItem, addedInfo *additionalInfo) error {
	pathToFile, err := codeFilePath(addedInfo.TemplateType, endpoint)
	if err != nil {
		return err
	}
	return c.writeFile(pathToFile, endpoint, endpointInfo, addedInfo)
}

// GenerateDoc is exported to indicate it's intended to be directly used.
func (c *fileCreator) GenerateDoc(endpoint string, endpointInfo *framework.OASPathItem, addedInfo *additionalInfo) error {
	pathToFile, err := docFilePath(addedInfo.TemplateType, endpoint)
	if err != nil {
		return err
	}
	// If the doc already exists, no need to generate a new one, especially
	// since these get hand-edited after being first created.
	if _, err := os.Stat(pathToFile); err == nil {
		// The file already exists, nothing further to do here.
		return nil
	}
	// From here on, addedInfo will be used to select the template to
	// use. Since we want it to be for docs, we need to update that now.
	addedInfo.TemplateType = templateTypeDoc
	return c.writeFile(pathToFile, endpoint, endpointInfo, addedInfo)
}

func (c *fileCreator) writeFile(pathToFile string, endpoint string, endpointInfo *framework.OASPathItem, addedInfo *additionalInfo) error {
	wr, closer, err := c.createFileWriter(pathToFile)
	if err != nil {
		return err
	}
	defer closer()
	return c.templateHandler.Write(wr, endpoint, endpointInfo, addedInfo)
}

// createFileWriter creates a file and returns its writer for the caller to use in templating.
// The closer will only be populated if the err is nil.
func (c *fileCreator) createFileWriter(pathToFile string) (wr *bufio.Writer, closer func(), err error) {
	var cleanups []func() error
	closer = func() {
		for _, cleanup := range cleanups {
			if err := cleanup(); err != nil {
				c.logger.Error(err.Error())
			}
		}
	}

	// Make the directory and file.
	if err := os.MkdirAll(filepath.Dir(pathToFile), generatedDirPerms); err != nil {
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
func codeFilePath(tmplType templateType, endpoint string) (string, error) {
	filename := fmt.Sprintf("%s%s.go", tmplType.String(), endpoint)
	homeDirPath, err := pathToHomeDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(homeDirPath, "generated", filename)
	return stripCurlyBraces(path), nil
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
func docFilePath(tmplType templateType, endpoint string) (string, error) {
	filename := fmt.Sprintf("%s%s.md", tmplType.String(), endpoint)
	homeDirPath, err := pathToHomeDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(homeDirPath, "website", "docs", "generated", filename)
	return stripCurlyBraces(path), nil
}

// stripCurlyBraces converts a path like
// "generated/resources/transform-transformation-{name}.go"
// to "generated/resources/transform-transformation-name.go".
func stripCurlyBraces(path string) string {
	path = strings.ReplaceAll(path, "{", "")
	path = strings.ReplaceAll(path, "}", "")
	return path
}

// pathToHomeDir yields the path to the terraform-vault-provider
// home directory on the machine on which it's running.
// ex. /home/your-name/go/src/github.com/terraform-providers/terraform-provider-vault
func pathToHomeDir() (string, error) {
	repoName := "terraform-provider-vault"
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	pathParts := strings.Split(wd, repoName)
	return pathParts[0] + repoName, nil
}
