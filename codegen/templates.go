package codegen

import (
	"fmt"
	"io/ioutil"

	"github.com/hashicorp/go-hclog"
)

// templatePaths is a registry of the template for each file type.
var templatePaths = map[FileType]string{
	FileTypeDataSource: "/codegen/templates/datasource.go.tpl",
	FileTypeResource:   "/codegen/templates/resource.go.tpl",
	FileTypeDoc:        "/codegen/templates/doc.md.tpl",
}

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

// templates is populated when the package initializes, and reads in
// all the templates that are available.
var templates = func() map[FileType]string {
	tmpls := make(map[FileType]string, len(templatePaths))
	for fileType, path := range templatePaths {
		pathToFile := pathToHomeDir + path
		b, err := ioutil.ReadFile(pathToFile)
		if err != nil {
			hclog.Default().Error(fmt.Sprintf("could not populate %q due to %q", pathToFile, err.Error()))
		}
		tmpls[fileType] = string(b)
	}
	return tmpls
}()
