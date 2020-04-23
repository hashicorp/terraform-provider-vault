package codegen

import (
	"testing"
)

// testPaths is a sampling of real paths that
// originate in the OpenAPI doc, pulled via:
// $ cat testdata/openapi.json | jq '.paths' | jq 'keys[]'
var testPaths = []string{
	"/database/roles",
	"/database/roles/{name}",
	"/auth/userpass/users/{username}/password",
	"/auth/userpass/users/{username}/policies",
	"/transit/export/{type}/{name}/{version}",
}

func TestCodeFilePath(t *testing.T) {
	expected := []struct {
		DataSourceFilePath string
		ResourceFilePath   string
	}{
		{
			DataSourceFilePath: "/generated/datasources/database/roles.go",
			ResourceFilePath:   "/generated/resources/database/roles.go",
		},
		{
			DataSourceFilePath: "/generated/datasources/database/roles/name.go",
			ResourceFilePath:   "/generated/resources/database/roles/name.go",
		},
		{
			DataSourceFilePath: "/generated/datasources/auth/userpass/users/username/password.go",
			ResourceFilePath:   "/generated/resources/auth/userpass/users/username/password.go",
		},
		{
			DataSourceFilePath: "/generated/datasources/auth/userpass/users/username/policies.go",
			ResourceFilePath:   "/generated/resources/auth/userpass/users/username/policies.go",
		},
		{
			DataSourceFilePath: "/generated/datasources/transit/export/type/name/version.go",
			ResourceFilePath:   "/generated/resources/transit/export/type/name/version.go",
		},
	}
	for i, testPath := range testPaths {
		actualDataSourceFilePath := codeFilePath(templateTypeDataSource, testPath)
		if actualDataSourceFilePath != pathToHomeDir+expected[i].DataSourceFilePath {
			t.Fatalf("expected %q but received %q", pathToHomeDir+expected[i].DataSourceFilePath, actualDataSourceFilePath)
		}
		actualResourceFilePath := codeFilePath(templateTypeResource, testPath)
		if actualResourceFilePath != pathToHomeDir+expected[i].ResourceFilePath {
			t.Fatalf("expected %q but received %q", pathToHomeDir+expected[i].ResourceFilePath, actualResourceFilePath)
		}
	}
}

func TestDocFilePath(t *testing.T) {
	expected := []struct {
		DataSourceFilePath string
		ResourceFilePath   string
	}{
		{
			DataSourceFilePath: "/website/docs/generated/datasources/database/roles.md",
			ResourceFilePath:   "/website/docs/generated/resources/database/roles.md",
		},
		{
			DataSourceFilePath: "/website/docs/generated/datasources/database/roles/name.md",
			ResourceFilePath:   "/website/docs/generated/resources/database/roles/name.md",
		},
		{
			DataSourceFilePath: "/website/docs/generated/datasources/auth/userpass/users/username/password.md",
			ResourceFilePath:   "/website/docs/generated/resources/auth/userpass/users/username/password.md",
		},
		{
			DataSourceFilePath: "/website/docs/generated/datasources/auth/userpass/users/username/policies.md",
			ResourceFilePath:   "/website/docs/generated/resources/auth/userpass/users/username/policies.md",
		},
		{
			DataSourceFilePath: "/website/docs/generated/datasources/transit/export/type/name/version.md",
			ResourceFilePath:   "/website/docs/generated/resources/transit/export/type/name/version.md",
		},
	}
	for i, testPath := range testPaths {
		actualDataSourceDocPath := docFilePath(templateTypeDataSource, testPath)
		if actualDataSourceDocPath != pathToHomeDir+expected[i].DataSourceFilePath {
			t.Fatalf("expected %q but received %q", pathToHomeDir+expected[i].DataSourceFilePath, actualDataSourceDocPath)
		}
		actualResourceDocPath := docFilePath(templateTypeResource, testPath)
		if actualResourceDocPath != pathToHomeDir+expected[i].ResourceFilePath {
			t.Fatalf("expected %q but received %q", pathToHomeDir+expected[i].ResourceFilePath, actualResourceDocPath)
		}
	}
}
