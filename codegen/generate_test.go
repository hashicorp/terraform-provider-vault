package codegen

import (
	"testing"
)

func TestCodeFilePath(t *testing.T) {
	homeDirPath, err := pathToHomeDir()
	if err != nil {
		t.Fatal(err)
	}
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
		actualDataSourceFilePath, err := codeFilePath(tfTypeDataSource, testCase.input)
		if err != nil {
			t.Fatal(err)
		}
		if actualDataSourceFilePath != homeDirPath+testCase.expectedDataSourceFilePath {
			t.Fatalf("expected %q but received %q", homeDirPath+testCase.expectedDataSourceFilePath, actualDataSourceFilePath)
		}
		actualResourceFilePath, err := codeFilePath(tfTypeResource, testCase.input)
		if err != nil {
			t.Fatal(err)
		}
		if actualResourceFilePath != homeDirPath+testCase.expectedResourceFilePath {
			t.Fatalf("expected %q but received %q", homeDirPath+testCase.expectedResourceFilePath, actualResourceFilePath)
		}
	}
}

func TestDocFilePath(t *testing.T) {
	homeDirPath, err := pathToHomeDir()
	if err != nil {
		t.Fatal(err)
	}

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
		actualDataSourceDocPath, err := docFilePath(tfTypeDataSource, testCase.input)
		if err != nil {
			t.Fatal(err)
		}
		if actualDataSourceDocPath != homeDirPath+testCase.expectedDataSourceFilePath {
			t.Fatalf("expected %q but received %q", homeDirPath+testCase.expectedDataSourceFilePath, actualDataSourceDocPath)
		}
		actualResourceDocPath, err := docFilePath(tfTypeResource, testCase.input)
		if err != nil {
			t.Fatal(err)
		}
		if actualResourceDocPath != homeDirPath+testCase.expectedResourceFilePath {
			t.Fatalf("expected %q but received %q", homeDirPath+testCase.expectedResourceFilePath, actualResourceDocPath)
		}
	}
}

func TestStripCurlyBraces(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{
			input:    "{test}",
			expected: "test",
		},
		{
			input:    "{{name}}",
			expected: "name",
		},
		{
			input:    "name",
			expected: "name",
		},
		{
			input:    "{name",
			expected: "name",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.input, func(t *testing.T) {
			actual := stripCurlyBraces(testCase.input)
			if actual != testCase.expected {
				t.Fatalf("expected %q but received %q", actual, testCase.expected)
			}
		})
	}
}
