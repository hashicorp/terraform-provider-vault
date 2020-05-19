package codegen

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
)

func TestClean(t *testing.T) {
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
			expected: "rolename",
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
	}
	for _, testCase := range testCases {
		t.Run(testCase.input, func(t *testing.T) {
			actual := clean(testCase.input)
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
				Parameters: []*templatableParam{
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
				Parameters: []*templatableParam{
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
				Parameters: []*templatableParam{
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
				Parameters: []*templatableParam{
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
			expectErr: true,
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
		expected        *templatableParam
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
			expected: &templatableParam{
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
			expected: &templatableParam{
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

func TestCollectParameters(t *testing.T) {
	endpointInfo := &framework.OASPathItem{}
	if err := json.Unmarshal([]byte(testEndpoint), endpointInfo); err != nil {
		t.Fatal(err)
	}
	parameters := collectParameters(endpointInfo)
	for i := 0; i < len(parameters); i++ {
		switch i {
		case 0:
			if parameters[0].Name != "name" {
				t.Fatalf("expected 'name' but received %q", parameters[0].Name)
			}
		case 1:
			if parameters[1].Name != "transformations" {
				t.Fatalf("expected 'transformations' but received %q", parameters[1].Name)
			}
		default:
			t.Fatalf("expected 2 parameters but received %d", len(parameters))
		}
	}
}

func TestTemplateHandler(t *testing.T) {
	h, err := newTemplateHandler(hclog.Default())
	if err != nil {
		t.Fatal(err)
	}
	endpointInfo := &framework.OASPathItem{}
	if err := json.Unmarshal([]byte(testEndpoint), endpointInfo); err != nil {
		t.Fatal(err)
	}
	buf := bytes.NewBuffer([]byte{})
	if err := h.Write(buf, templateTypeResource, "/transform/role/{name}", endpointInfo); err != nil {
		t.Fatal(err)
	}
	result := ""
	chunk := make([]byte, 500)
	for {
		_, err := buf.Read(chunk)
		if err != nil {
			if err == io.EOF {
				result += string(chunk)
				break
			}
			t.Fatal(err)
		}
		result += string(chunk)
	}
	// We only spot check here because resources will be covered by their
	// own tests fully testing validity. This test is mainly to make sure
	// we're getting something that looks correct back rather than an empty
	// string.
	if !strings.Contains(result, "resourceNameExists") {
		t.Fatalf("unexpected result: %s", result)
	}
}

// based on "/transform/role/{name}"
const testEndpoint = `{
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
}`
