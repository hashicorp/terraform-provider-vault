package codegen

type templateType int

const (
	templateTypeUnset templateType = iota
	templateTypeDataSource
	templateTypeResource
	templateTypeDoc
)

func (t templateType) String() string {
	switch t {
	case templateTypeDataSource:
		return "datasources"
	case templateTypeResource:
		return "resources"
	case templateTypeDoc:
		return "docs"
	}
	return "unset"
}
