package codegen

import (
	"fmt"
	"github.com/hashicorp/go-hclog"
	"html/template"
	"io/ioutil"
)

// templateRegistry is a registry of the template for each file type.
var (
	templateRegistry = map[FileType]string{
		FileTypeDataSource: "/codegen/templates/datasource.go.tpl",
		FileTypeResource:   "/codegen/templates/resource.go.tpl",
		FileTypeDoc:        "/codegen/templates/doc.md.tpl",
	}

	templateSupplier = &supplier{}
)

type FileType int

const (
	FileTypeDataSource FileType = iota
	FileTypeResource
	FileTypeDoc
)

func (t FileType) String() string {
	switch t {
	case FileTypeDataSource:
		return "datasources"
	case FileTypeResource:
		return "resources"
	}
	return "docs"
}

type supplier struct {
	templates map[FileType]*template.Template
}

// TODO this all kind of sucks, I think I should populate templates early on in the running process
// rather than trying to do it at a package init level where I can't return errs.
func (s *supplier) Template(logger hclog.Logger, fileType FileType) (*template.Template, error) {
	if s.templates == nil {
		s.templates = s.readTemplates(logger)
	}
	tpl, ok := s.templates[fileType]
	if !ok {
		return nil, fmt.Errorf("no template for %q, please check for previous errors around %q or %q", fileType, templateRegistry[fileType], fileType)
	}
	return tpl, nil
}

// templates is populated when the package initializes, and reads in
// all the templates that are available.
func (s *supplier) readTemplates(logger hclog.Logger) map[FileType]*template.Template {
	tmpls := make(map[FileType]*template.Template, len(templateRegistry))
	for fileType, path := range templateRegistry {
		pathToFile := pathToHomeDir + path
		b, err := ioutil.ReadFile(pathToFile)
		if err != nil {
			if logger.IsError() {
				logger.Error(fmt.Sprintf("unable to read %q: %s", pathToFile, err))
				continue
			}
		}
		t, err := template.New(fileType.String()).Parse(string(b))
		if err != nil {
			if logger.IsError() {
				logger.Error(fmt.Sprintf("unable to parse %q: %s", fileType, err))
				continue
			}
		}
		tmpls[fileType] = t
	}
	return tmpls
}
