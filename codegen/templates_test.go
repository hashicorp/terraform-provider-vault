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
		actual := clean(testCase.input)
		if actual != testCase.expected {
			t.Fatalf("input: %q; expected: %q; actual: %q", testCase.input, testCase.expected, actual)
		}
	}
}

func TestValidate(t *testing.T) {
	testCases := []struct {
		input       *templatableEndpoint
		expectedErr string
	}{
		{
			input:       nil,
			expectedErr: "endpoint is nil",
		},
		{
			input:       &templatableEndpoint{},
			expectedErr: "endpoint cannot be blank for &{Endpoint: DirName: UpperCaseDifferentiator: LowerCaseDifferentiator: Parameters:[] SupportsRead:false SupportsWrite:false SupportsDelete:false}",
		},
		{
			input: &templatableEndpoint{
				Endpoint: "foo",
			},
			expectedErr: "dirname cannot be blank for &{Endpoint:foo DirName: UpperCaseDifferentiator: LowerCaseDifferentiator: Parameters:[] SupportsRead:false SupportsWrite:false SupportsDelete:false}",
		},
		{
			input: &templatableEndpoint{
				Endpoint: "foo",
				DirName:  "foo",
			},
			expectedErr: "exported function prefix cannot be blank for &{Endpoint:foo DirName:foo UpperCaseDifferentiator: LowerCaseDifferentiator: Parameters:[] SupportsRead:false SupportsWrite:false SupportsDelete:false}",
		},
		{
			input: &templatableEndpoint{
				Endpoint:                "foo",
				DirName:                 "foo",
				UpperCaseDifferentiator: "foo",
			},
			expectedErr: "private function prefix cannot be blank for &{Endpoint:foo DirName:foo UpperCaseDifferentiator:foo LowerCaseDifferentiator: Parameters:[] SupportsRead:false SupportsWrite:false SupportsDelete:false}",
		},
		{
			input: &templatableEndpoint{
				Endpoint:                "foo",
				DirName:                 "foo",
				UpperCaseDifferentiator: "foo",
				LowerCaseDifferentiator: "foo",
			},
			expectedErr: "",
		},
		{
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
			expectedErr: "unsupported type of foo for some-param",
		},
		{
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
			expectedErr: "",
		},
		{
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
			expectedErr: "",
		},
		{
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
			expectedErr: "unsupported array type of object for foo",
		},
	}
	for _, testCase := range testCases {
		shouldErr := testCase.expectedErr != ""
		err := testCase.input.Validate()
		if err != nil {
			if err.Error() != testCase.expectedErr {
				t.Fatalf("input: %+v; expected err: %q; actual: %q", testCase.input, testCase.expectedErr, err)
			}
		} else {
			if shouldErr {
				t.Fatalf("expected an error for %+v", testCase.input)
			}
		}
	}
}

func TestToTemplatableParam(t *testing.T) {
	type input struct {
		param           framework.OASParameter
		isPathParameter bool
	}
	testCases := []struct {
		input    *input
		expected *templatableParam
	}{
		{
			input: &input{
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
			},
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
			input: &input{
				param: framework.OASParameter{
					Name:        "",
					Description: "",
					In:          "",
					Required:    false,
					Deprecated:  false,
				},
				isPathParameter: false,
			},
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
		actual := toTemplatableParam(testCase.input.param, testCase.input.isPathParameter)
		if !reflect.DeepEqual(testCase.expected, actual) {
			t.Fatalf("expected %+v but received %+v", testCase.expected, actual)
		}
	}
}

func TestCollectParameters(t *testing.T) {
	endpointInfo := &framework.OASPathItem{}
	if err := json.Unmarshal([]byte(testEndpoint), endpointInfo); err != nil {
		t.Fatal(err)
	}
	parameters := collectParameters(endpointInfo, &additionalInfo{})
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
	if err := h.Write(buf, "role", "/transform/role/{name}", endpointInfo, &additionalInfo{TemplateType: templateTypeResource}); err != nil {
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
