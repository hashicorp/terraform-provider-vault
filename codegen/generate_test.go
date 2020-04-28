package codegen

import (
	"testing"
)

func TestCodeFilePath(t *testing.T) {
	testCases := []struct {
		input                      string
		expectedDataSourceFilePath string
		expectedResourceFilePath   string
	}{
		{
			input:                      "/database/roles",
			expectedDataSourceFilePath: "/generated/datasources/database/roles.go",
			expectedResourceFilePath:   "/generated/resources/database/roles.go",
		},
		{
			input:                      "/database/roles/{name}",
			expectedDataSourceFilePath: "/generated/datasources/database/roles/name.go",
			expectedResourceFilePath:   "/generated/resources/database/roles/name.go",
		},
		{
			input:                      "/auth/userpass/users/{username}/password",
			expectedDataSourceFilePath: "/generated/datasources/auth/userpass/users/username/password.go",
			expectedResourceFilePath:   "/generated/resources/auth/userpass/users/username/password.go",
		},
		{
			input:                      "/auth/userpass/users/{username}/policies",
			expectedDataSourceFilePath: "/generated/datasources/auth/userpass/users/username/policies.go",
			expectedResourceFilePath:   "/generated/resources/auth/userpass/users/username/policies.go",
		},
		{
			input:                      "/transit/export/{type}/{name}/{version}",
			expectedDataSourceFilePath: "/generated/datasources/transit/export/type/name/version.go",
			expectedResourceFilePath:   "/generated/resources/transit/export/type/name/version.go",
		},
	}
	for _, testCase := range testCases {
		actualDataSourceFilePath := codeFilePath(templateTypeDataSource, testCase.input)
		if actualDataSourceFilePath != pathToHomeDir+testCase.expectedDataSourceFilePath {
			t.Fatalf("testCases %q but received %q", pathToHomeDir+testCase.expectedDataSourceFilePath, actualDataSourceFilePath)
		}
		actualResourceFilePath := codeFilePath(templateTypeResource, testCase.input)
		if actualResourceFilePath != pathToHomeDir+testCase.expectedResourceFilePath {
			t.Fatalf("testCases %q but received %q", pathToHomeDir+testCase.expectedResourceFilePath, actualResourceFilePath)
		}
	}
}

func TestDocFilePath(t *testing.T) {
	testCases := []struct {
		input                      string
		expectedDataSourceFilePath string
		expectedResourceFilePath   string
	}{
		{
			input:                      "/database/roles",
			expectedDataSourceFilePath: "/website/docs/generated/datasources/database/roles.md",
			expectedResourceFilePath:   "/website/docs/generated/resources/database/roles.md",
		},
		{
			input:                      "/database/roles/{name}",
			expectedDataSourceFilePath: "/website/docs/generated/datasources/database/roles/name.md",
			expectedResourceFilePath:   "/website/docs/generated/resources/database/roles/name.md",
		},
		{
			input:                      "/auth/userpass/users/{username}/password",
			expectedDataSourceFilePath: "/website/docs/generated/datasources/auth/userpass/users/username/password.md",
			expectedResourceFilePath:   "/website/docs/generated/resources/auth/userpass/users/username/password.md",
		},
		{
			input:                      "/auth/userpass/users/{username}/policies",
			expectedDataSourceFilePath: "/website/docs/generated/datasources/auth/userpass/users/username/policies.md",
			expectedResourceFilePath:   "/website/docs/generated/resources/auth/userpass/users/username/policies.md",
		},
		{
			input:                      "/transit/export/{type}/{name}/{version}",
			expectedDataSourceFilePath: "/website/docs/generated/datasources/transit/export/type/name/version.md",
			expectedResourceFilePath:   "/website/docs/generated/resources/transit/export/type/name/version.md",
		},
	}
	for _, testCase := range testCases {
		actualDataSourceDocPath := docFilePath(templateTypeDataSource, testCase.input)
		if actualDataSourceDocPath != pathToHomeDir+testCase.expectedDataSourceFilePath {
			t.Fatalf("testCases %q but received %q", pathToHomeDir+testCase.expectedDataSourceFilePath, actualDataSourceDocPath)
		}
		actualResourceDocPath := docFilePath(templateTypeResource, testCase.input)
		if actualResourceDocPath != pathToHomeDir+testCase.expectedResourceFilePath {
			t.Fatalf("testCases %q but received %q", pathToHomeDir+testCase.expectedResourceFilePath, actualResourceDocPath)
		}
	}
}
