package codegen

var AllowedPaths = map[string]FileType{
	// Data sources, alphabetized.
	"/transform/decode/{role_name}": FileTypeDataSource,
	"/transform/encode/{role_name}": FileTypeDataSource,

	// Resources, alphabetized.
	"/transform/alphabet":              FileTypeResource,
	"/transform/alphabet/{name}":       FileTypeResource,
	"/transform/role":                  FileTypeResource,
	"/transform/role/{name}":           FileTypeResource,
	"/transform/template":              FileTypeResource,
	"/transform/template/{name}":       FileTypeResource,
	"/transform/transformation":        FileTypeResource,
	"/transform/transformation/{name}": FileTypeResource,
}
