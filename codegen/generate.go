package codegen

import (
	"bufio"
	"errors"
	"fmt"
	"html/template"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/strutil"
)

var (
	ErrUnsupported = errors.New("code and doc generation for this item is unsupported")

	// These are the types of fields that OpenAPI has that we support
	// converting into Terraform fields.
	supportedParamTypes = []string{
		"array", // We presently only support string arrays.
		"boolean",
		"integer",
		"string",
	}

	pathToHomeDir = func() string {
		repoName := "terraform-provider-vault"
		wd, _ := os.Getwd()
		pathParts := strings.Split(wd, repoName)
		return pathParts[0] + repoName
	}()
)

// GenerateFiles is used to generate the code and doc for one single resource
// or data source. For example, if you provided it with the path
// "/transform/transformation/{name}" and a fileType of Resource, it would
// generate both the Go code for the resource, and a starter doc for it.
// Tests are not generated at this time because we'd prefer human eyes and hands
// on the generated code before including it in the provider.
func GenerateFiles(logger hclog.Logger, fileType FileType, vaultPath string, vaultPathDesc *framework.OASPathItem) error {
	if err := generateCode(logger, fileType, vaultPath, vaultPathDesc); err != nil {
		return err
	}
	if err := generateDoc(logger, fileType, vaultPath, vaultPathDesc); err != nil {
		return err
	}
	return nil
}

// generateCode generates the code for either one resource, or one data source.
func generateCode(logger hclog.Logger, fileType FileType, path string, pathItem *framework.OASPathItem) error {
	pathToFile := codeFilePath(fileType, path)
	return generateFile(logger, pathToFile, fileType, path, pathItem)
}

/*
codeFilePath creates a directory structure inside the "generated" folder that's
intended to make it easy to find the file for each endpoint in Vault, even if
we eventually cover all >500 of them and add tests.

	terraform-provider-vault/generated$ tree
	.
	├── datasources
	│   └── transform
	│       ├── decode
	│       │   └── role_name.go
	│       └── encode
	│           └── role_name.go
	└── resources
		└── transform
			├── alphabet
			│   └── name.go
			├── alphabet.go
			├── role
			│   └── name.go
			├── role.go
			├── template
			│   └── name.go
			├── template.go
			├── transformation
			│   └── name.go
			└── transformation.go
*/
func codeFilePath(fileType FileType, path string) string {
	return stripCurlyBraces(fmt.Sprintf("%s/generated/%s%s.go", pathToHomeDir, fileType.String(), path))
}

// generateDoc generates the doc for a resource or data source.
// The file is incomplete with a number of placeholders for the author to fill in
// additional information.
func generateDoc(logger hclog.Logger, fileType FileType, path string, pathItem *framework.OASPathItem) error {
	pathToFile := docFilePath(fileType, path)
	return generateFile(logger, pathToFile, FileTypeDoc, path, pathItem)
}

/*
docFilePath creates a directory structure inside the "website/docs/generated" folder
that's intended to make it easy to find the file for each endpoint in Vault, even if
we eventually cover all >500 of them and add tests.

	terraform-provider-vault/website/docs/generated$ tree
	.
	├── datasources
	│   └── transform
	│       ├── decode
	│       │   └── role_name.md
	│       └── encode
	│           └── role_name.md
	└── resources
		└── transform
			├── alphabet
			│   └── name.md
			├── alphabet.md
			├── role
			│   └── name.md
			├── role.md
			├── template
			│   └── name.md
			├── template.md
			├── transformation
			│   └── name.md
			└── transformation.md
 */
func docFilePath(fileType FileType, path string) string {
	result := fmt.Sprintf("%s/website/docs/generated/%s/%s.md", pathToHomeDir, fileType.String(), path)
	return stripCurlyBraces(result)
}

func generateFile(logger hclog.Logger, pathToFile string, fileType FileType, vaultPath string, vaultPathDesc *framework.OASPathItem) error {
	parentDir := pathToFile[:strings.LastIndex(pathToFile, "/")]
	if err := os.MkdirAll(parentDir, 0775); err != nil {
		return err
	}
	f, err := os.Create(pathToFile)
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); err != nil {
			logger.Error(err.Error())
		}
	}()
	wr := bufio.NewWriter(f)
	defer func() {
		if err := wr.Flush(); err != nil {
			logger.Error(err.Error())
		}
	}()
	if err := parseTemplate(logger, wr, fileType, parentDir, vaultPath, vaultPathDesc); err != nil {
		return err
	}
	return nil
}

// parseTemplate takes one pathItem and uses a template to generate text
// for it. This template is written to the given writer.
func parseTemplate(logger hclog.Logger, writer io.Writer, fileType FileType, parentDir string, vaultPath string, vaultPathDesc *framework.OASPathItem) error {
	tmpl, err := template.New(fileType.String()).Parse(templates[fileType])
	if err != nil {
		return err
	}
	tmplFriendly, err := toTemplateFriendly(logger, vaultPath, parentDir, vaultPathDesc)
	if err != nil {
		return err
	}
	return tmpl.Execute(writer, tmplFriendly)
}

// templateFriendlyPathItem is a convenience struct that plays nicely with Go's
// template package.
type templateFriendlyPathItem struct {
	Endpoint           string
	DirName            string
	ExportedFuncPrefix string
	PrivateFuncPrefix  string
	Parameters         []*templateFriendlyParameter
	SupportsRead       bool
	SupportsWrite      bool
	SupportsDelete     bool
}

type templateFriendlyParameter struct {
	*framework.OASParameter
	ForceNew bool
}

// toTemplateFriendly does a bunch of work to format the given data into a
// struct that has fields that will be idiomatic to use with Go's templating
// language.
func toTemplateFriendly(logger hclog.Logger, path, parentDir string, pathItem *framework.OASPathItem) (*templateFriendlyPathItem, error) {
	// Isolate the last field in the path and use it to prefix functions
	// to prevent naming collisions if there are multiple files in the same
	// directory.
	pathFields := strings.Split(path, "/")
	prefix := pathFields[0]
	if len(pathFields) > 1 {
		prefix = pathFields[len(pathFields)-1]
	}
	prefix = stripCurlyBraces(prefix)

	// We don't want snake case for the field name in Go code.
	prefix = strings.Replace(prefix, "_", "", -1)

	// Make the parameters easier to work with in Go's templating
	// language.
	friendlyParams := toTemplateFriendlyParameters(pathItem)

	// Validate that we don't have any unsupported types of parameters.
	for _, param := range friendlyParams {
		if !strutil.StrListContains(supportedParamTypes, param.Schema.Type) {
			logger.Error(fmt.Sprintf(`can't generate %q because parameter type of %q for %s is unsupported'`, path, param.Schema.Type, param.Name))
			return nil, ErrUnsupported
		}
	}

	// Sort the parameters by name so they won't shift every time
	// new files are generated due to having originated in maps.
	sort.Slice(friendlyParams, func(i, j int) bool {
		return friendlyParams[i].Name < friendlyParams[j].Name
	})
	return &templateFriendlyPathItem{
		Endpoint:           path,
		DirName:            parentDir[strings.LastIndex(parentDir, "/")+1:],
		ExportedFuncPrefix: strings.Title(strings.ToLower(prefix)),
		PrivateFuncPrefix:  strings.ToLower(prefix),
		Parameters:         friendlyParams,
		SupportsRead:       pathItem.Get != nil,
		SupportsWrite:      pathItem.Post != nil,
		SupportsDelete:     pathItem.Delete != nil,
	}, nil
}

// Parameters can be buried deep in the post request body. For
// convenience during templating, we dig down and grab those,
// and just put them at the top level with the rest.
func toTemplateFriendlyParameters(pathItem *framework.OASPathItem) []*templateFriendlyParameter {
	var result []*templateFriendlyParameter

	// There can be dupe parameters at the top level and inside the post
	// body. Top level parameters are path parameters, whereas the added
	// ones in the post body are not.
	unique := make(map[string]bool)
	for _, param := range pathItem.Parameters {
		// We can assume these are already unique because they originated
		// from a map where the key was their name.
		if param.Schema == nil {
			// Always populate schema and display attributes so later it'll be easier
			// to check if they're sensitive by iterating over them.
			param.Schema = &framework.OASSchema{}
		}
		if param.Schema.DisplayAttrs == nil {
			param.Schema.DisplayAttrs = &framework.DisplayAttributes{}
		}
		result = append(result, &templateFriendlyParameter{
			OASParameter: &param,
			// All top-level parameters are path parameters, so if they change
			// we're talking about something entirely new/else.
			ForceNew: true,
		})
		unique[param.Name] = true
	}
	if pathItem.Post == nil {
		return result
	}
	if pathItem.Post.RequestBody == nil {
		return result
	}
	if pathItem.Post.RequestBody.Content == nil {
		return result
	}
	for _, mediaTypeObject := range pathItem.Post.RequestBody.Content {
		if mediaTypeObject.Schema == nil {
			continue
		}
		if mediaTypeObject.Schema.Properties == nil {
			continue
		}
		for propertyName, schema := range mediaTypeObject.Schema.Properties {
			if ok := unique[propertyName]; ok {
				continue
			}
			if schema == nil {
				// Always populate schema and display attributes so later it'll be easier
				// to check if they're sensitive by iterating over them.
				schema = &framework.OASSchema{}
			}
			if schema.DisplayAttrs == nil {
				schema.DisplayAttrs = &framework.DisplayAttributes{}
			}
			result = append(result, &templateFriendlyParameter{
				OASParameter: &framework.OASParameter{
					Name:        propertyName,
					Description: schema.Description,
					In:          "post",
					Schema:      schema,
				},
				ForceNew: false,
			})
			unique[propertyName] = true
		}
	}
	return result
}

// replaceSlashesWithDashes converts a path like "/transform/transformation/{name}"
// to "transform-transformation-{name}". Note that it trims leading slashes.
func replaceSlashesWithDashes(s string) string {
	if strings.HasPrefix(s, "/") {
		s = s[1:]
	}
	return strings.Replace(s, "/", "-", -1)
}

// stripCurlyBraces converts a path like
// "generated/resources/transform-transformation-{name}.go"
// to "generated/resources/transform-transformation-name.go".
func stripCurlyBraces(path string) string {
	path = strings.Replace(path, "{", "", -1)
	path = strings.Replace(path, "}", "", -1)
	return path
}
