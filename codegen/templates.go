package codegen

type templateType int

const (
	templateTypeDataSource templateType = iota
	templateTypeResource
	templateTypeDoc
)

func (t templateType) String() string {
	switch t {
	case templateTypeDataSource:
		return "datasources"
	case templateTypeResource:
		return "resources"
	}
	return "docs"
}
