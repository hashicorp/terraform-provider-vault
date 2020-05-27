package codegen

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
)

func TestFormat(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{
			input:    "alphabet",
			expected: "alphabet",
		},
		{
			input:    "{name}",
			expected: "name",
		},
		{
			input:    "{role_name}",
			expected: "roleName",
		},
		{
			input:    "{name}",
			expected: "name",
		},
		{
			input:    "{version}",
			expected: "version",
		},
		{
			input:    "unlikely",
			expected: "unlikely",
		},
		{
			input:    "{role_name_}",
			expected: "roleName",
		},
		{
			input:    "{role__name}",
			expected: "roleName",
		},
		{
			input:    "{role_name_here}",
			expected: "roleNameHere",
		},
		{
			input:    "{rOlE_nAmE}",
			expected: "roleName",
		},
		{
			input:    "{ROLE_NAME}",
			expected: "roleName",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.input, func(t *testing.T) {
			actual := format(testCase.input)
			if actual != testCase.expected {
				t.Fatalf("input: %q; expected: %q; actual: %q", testCase.input, testCase.expected, actual)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	testCases := []struct {
		testName  string
		input     *templatableEndpoint
		expectErr bool
	}{
		{
			testName:  "nil inputs error",
			input:     nil,
			expectErr: true,
		},
		{
			testName:  "blank endpoints error",
			input:     &templatableEndpoint{},
			expectErr: true,
		},
		{
			testName: "blank dirnames error",
			input: &templatableEndpoint{
				Endpoint: "foo",
			},
			expectErr: true,
		},
		{
			testName: "blank upper case differentiators error",
			input: &templatableEndpoint{
				Endpoint: "foo",
				DirName:  "foo",
			},
			expectErr: true,
		},
		{
			testName: "blank lower case differentiators error",
			input: &templatableEndpoint{
				Endpoint:                "foo",
				DirName:                 "foo",
				UpperCaseDifferentiator: "foo",
			},
			expectErr: true,
		},
		{
			testName: "valid endpoint",
			input: &templatableEndpoint{
				Endpoint:                "foo",
				DirName:                 "foo",
				UpperCaseDifferentiator: "foo",
				LowerCaseDifferentiator: "foo",
			},
			expectErr: false,
		},
		{
			testName: "bad parameter type",
			input: &templatableEndpoint{
				Endpoint:                "foo",
				DirName:                 "foo",
				UpperCaseDifferentiator: "foo",
				LowerCaseDifferentiator: "foo",
				Parameters: []templatableParam{
					{
						OASParameter: &framework.OASParameter{
							Name: "some-param",
							Schema: &framework.OASSchema{
								Type: "foo",
							},
						},
					},
				},
			},
			expectErr: true,
		},
		{
			testName: "good parameter type",
			input: &templatableEndpoint{
				Endpoint:                "foo",
				DirName:                 "foo",
				UpperCaseDifferentiator: "foo",
				LowerCaseDifferentiator: "foo",
				Parameters: []templatableParam{
					{
						OASParameter: &framework.OASParameter{
							Name: "some-param",
							Schema: &framework.OASSchema{
								Type: "string",
							},
						},
					},
				},
			},
			expectErr: false,
		},
		{
			testName: "array of strings param",
			input: &templatableEndpoint{
				Endpoint:                "foo",
				DirName:                 "foo",
				UpperCaseDifferentiator: "foo",
				LowerCaseDifferentiator: "foo",
				Parameters: []templatableParam{
					{
						OASParameter: &framework.OASParameter{
							Name: "foo",
							Schema: &framework.OASSchema{
								Type: "array",
								Items: &framework.OASSchema{
									Type: "string",
								},
							},
						},
					},
				},
			},
			expectErr: false,
		},
		{
			testName: "array of objects param",
			input: &templatableEndpoint{
				Endpoint:                "foo",
				DirName:                 "foo",
				UpperCaseDifferentiator: "foo",
				LowerCaseDifferentiator: "foo",
				Parameters: []templatableParam{
					{
						OASParameter: &framework.OASParameter{
							Name: "foo",
							Schema: &framework.OASSchema{
								Type: "array",
								Items: &framework.OASSchema{
									Type: "object",
								},
							},
						},
					},
				},
			},
			expectErr: false,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.testName, func(t *testing.T) {
			err := testCase.input.Validate()
			if testCase.expectErr && err == nil {
				t.Fatalf("err expected, got nil")
			}
			if !testCase.expectErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}
		})
	}
}

func TestToTemplatableParam(t *testing.T) {
	testCases := []struct {
		param           framework.OASParameter
		isPathParameter bool
		expected        templatableParam
	}{
		{
			param: framework.OASParameter{
				Name:        "name",
				Description: "description",
				In:          "in",
				Schema: &framework.OASSchema{
					Type:        "type",
					Description: "description",
					Properties: map[string]*framework.OASSchema{
						"something": {Description: "schema"},
					},
					Required: []string{"a"},
					Items: &framework.OASSchema{
						Description: "schema",
					},
					Format:           "format",
					Pattern:          "pattern",
					Enum:             []interface{}{"enum"},
					Default:          "default",
					Example:          "example",
					Deprecated:       true,
					DisplayValue:     "displayvalue",
					DisplaySensitive: true,
					DisplayGroup:     "displaygroup",
					DisplayAttrs: &framework.DisplayAttributes{
						Name:       "foo",
						Value:      true,
						Sensitive:  true,
						Navigation: true,
						Group:      "group",
						Action:     "action",
					},
				},
				Required:   true,
				Deprecated: true,
			},
			isPathParameter: true,
			expected: templatableParam{
				OASParameter: &framework.OASParameter{
					Name:        "name",
					Description: "description",
					In:          "in",
					Schema: &framework.OASSchema{
						Type:        "type",
						Description: "description",
						Properties: map[string]*framework.OASSchema{
							"something": {Description: "schema"},
						},
						Required: []string{"a"},
						Items: &framework.OASSchema{
							Description: "schema",
						},
						Format:           "format",
						Pattern:          "pattern",
						Enum:             []interface{}{"enum"},
						Default:          "default",
						Example:          "example",
						Deprecated:       true,
						DisplayValue:     "displayvalue",
						DisplaySensitive: true,
						DisplayGroup:     "displaygroup",
						DisplayAttrs: &framework.DisplayAttributes{
							Name:       "foo",
							Value:      true,
							Sensitive:  true,
							Navigation: true,
							Group:      "group",
							Action:     "action",
						},
					},
					Required:   true,
					Deprecated: true,
				},
				IsPathParam: true,
			},
		},
		{
			param: framework.OASParameter{
				Name:        "",
				Description: "",
				In:          "",
				Required:    false,
				Deprecated:  false,
			},
			isPathParameter: false,
			expected: templatableParam{
				OASParameter: &framework.OASParameter{
					Name:        "",
					Description: "",
					In:          "",
					Schema: &framework.OASSchema{
						DisplayAttrs: &framework.DisplayAttributes{},
					},
					Required:   false,
					Deprecated: false,
				},
				IsPathParam: false,
			},
		},
	}
	for _, testCase := range testCases {
		actual := toTemplatableParam(testCase.param, testCase.isPathParameter)
		if !reflect.DeepEqual(testCase.expected, actual) {
			t.Fatalf("expected %#v but received %#v", testCase.expected, actual)
		}
	}
}

func TestParseParameters(t *testing.T) {
	testCases := []struct {
		testName       string
		endpointInfo   string
		expectedParams []string
	}{
		{
			testName: "/transform/role/{name}",
			endpointInfo: `{
	"description": "Read, write, and delete roles.",
	"parameters": [{
		"name": "name",
		"description": "The name of the role.",
		"in": "path",
		"schema": {
			"type": "string"
		},
		"required": true
	}],
	"x-vault-createSupported": true,
	"get": {
		"operationId": "getTransformRoleName",
		"tags": [
			"secrets"
		],
		"responses": {
			"200": {
				"description": "OK"
			}
		}
	},
	"post": {
		"operationId": "postTransformRoleName",
		"tags": [
			"secrets"
		],
		"requestBody": {
			"content": {
				"application/json": {
					"schema": {
						"type": "object",
						"properties": {
							"transformations": {
								"type": "array",
								"description": "A comma separated string or slice of transformations to use.",
								"items": {
									"type": "string"
								}
							}
						}
					}
				}
			}
		},
		"responses": {
			"200": {
				"description": "OK"
			}
		}
	},
	"delete": {
		"operationId": "deleteTransformRoleName",
		"tags": [
			"secrets"
		],
		"responses": {
			"204": {
				"description": "empty body"
			}
		}
	}
}`,
			expectedParams: []string{"name", "transformations"},
		},
		{
			testName: "/transform/alphabet/{name}",
			endpointInfo: `{
	"description": "Read, write, and delete alphabets.",
	"parameters": [{
		"name": "name",
		"description": "The name of the alphabet.",
		"in": "path",
		"schema": {
			"type": "string"
		},
		"required": true
	}],
	"x-vault-createSupported": true,
	"get": {
		"operationId": "getTransformAlphabetName",
		"tags": [
			"secrets"
		],
		"responses": {
			"200": {
				"description": "OK"
			}
		}
	},
	"post": {
		"operationId": "postTransformAlphabetName",
		"tags": [
			"secrets"
		],
		"requestBody": {
			"content": {
				"application/json": {
					"schema": {
						"type": "object",
						"properties": {
							"alphabet": {
								"type": "string",
								"description": "A string of characters that contains the alphabet set."
							}
						}
					}
				}
			}
		},
		"responses": {
			"200": {
				"description": "OK"
			}
		}
	},
	"delete": {
		"operationId": "deleteTransformAlphabetName",
		"tags": [
			"secrets"
		],
		"responses": {
			"204": {
				"description": "empty body"
			}
		}
	}
}`,
			expectedParams: []string{"alphabet", "name"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.testName, func(t *testing.T) {
			endpointInfo := &framework.OASPathItem{}
			if err := json.Unmarshal([]byte(testCase.endpointInfo), endpointInfo); err != nil {
				t.Fatal(err)
			}
			parameters := parseParameters(endpointInfo, &additionalInfo{Type: tfTypeResource})
			if len(parameters) != len(testCase.expectedParams) {
				t.Fatalf("expected %d parameters but received %d", len(testCase.expectedParams), len(parameters))
			}
			for i := 0; i < len(parameters); i++ {
				if parameters[i].Name != testCase.expectedParams[i] {
					t.Fatalf("expected %q but received %q", testCase.expectedParams[i], parameters[i].Name)
				}
			}
		})
	}
}

func TestTemplateHandler(t *testing.T) {
	h, err := newTemplateHandler(hclog.Default())
	if err != nil {
		t.Fatal(err)
	}
	endpointInfo := &framework.OASPathItem{}
	if err := json.Unmarshal([]byte(`{
	"description": "Read, write, and delete roles.",
	"parameters": [{
		"name": "name",
		"description": "The name of the role.",
		"in": "path",
		"schema": {
			"type": "string"
		},
		"required": true
	}],
	"x-vault-createSupported": true,
	"get": {
		"operationId": "getTransformRoleName",
		"tags": [
			"secrets"
		],
		"responses": {
			"200": {
				"description": "OK"
			}
		}
	},
	"post": {
		"operationId": "postTransformRoleName",
		"tags": [
			"secrets"
		],
		"requestBody": {
			"content": {
				"application/json": {
					"schema": {
						"type": "object",
						"properties": {
							"transformations": {
								"type": "array",
								"description": "A comma separated string or slice of transformations to use.",
								"items": {
									"type": "string"
								}
							}
						}
					}
				}
			}
		},
		"responses": {
			"200": {
				"description": "OK"
			}
		}
	},
	"delete": {
		"operationId": "deleteTransformRoleName",
		"tags": [
			"secrets"
		],
		"responses": {
			"204": {
				"description": "empty body"
			}
		}
	}
}`), endpointInfo); err != nil {
		t.Fatal(err)
	}
	b := &strings.Builder{}
	if err := h.Write(b, templateTypeResource, "/transform/role/{name}", endpointInfo, &additionalInfo{
		Type: tfTypeResource,
	}); err != nil {
		t.Fatal(err)
	}
	result := b.String()

	// We only spot check here because resources will be covered by their
	// own tests fully testing validity. This test is mainly to make sure
	// we're getting something that looks correct back rather than an empty
	// string.
	if !strings.Contains(result, "resourceNameExists") {
		t.Fatalf("unexpected result: %s", result)
	}
}
