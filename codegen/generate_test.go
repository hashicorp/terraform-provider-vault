package codegen

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
)

const (
	examplePath     = `/transform/transformation/{name}`
	examplePathItem = `{
  "description": "Read, write, and delete transformations",
  "parameters": [
    {
      "name": "name",
      "description": "The name of the transformation.",
      "in": "path",
      "schema": {
        "type": "string"
      },
      "required": true
    }
  ],
  "x-vault-createSupported": true,
  "get": {
    "operationId": "getTransformTransformationName",
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
    "operationId": "postTransformTransformationName",
    "tags": [
      "secrets"
    ],
    "requestBody": {
      "content": {
        "application/json": {
          "schema": {
            "type": "object",
            "properties": {
              "allowed_roles": {
                "type": "array",
                "description": "The set of roles allowed to perform this transformation.",
                "items": {
                  "type": "string"
                }
              },
              "masking_character": {
                "type": "string",
                "description": "The character used to replace data when in masking mode"
              },
              "template": {
                "type": "string",
                "description": "The name of the template to use."
              },
              "tweak_source": {
                "type": "string",
                "description": "The source of where the tweak value comes from. Only valid when in FPE mode."
              },
              "type": {
                "type": "string",
                "description": "The type of transformation to perform."
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
    "operationId": "deleteTransformTransformationName",
    "tags": [
      "secrets"
    ],
    "responses": {
      "204": {
        "description": "empty body"
      }
    }
  }
}
`
)

func TestGenerateResource(t *testing.T) {
	pathItem := &framework.OASPathItem{}
	if err := json.NewDecoder(bytes.NewReader([]byte(examplePathItem))).Decode(pathItem); err != nil {
		t.Fatal(err)
	}
	if err := parseTemplate(hclog.Default(), os.Stdout, FileTypeResource, "fooDir", examplePath, pathItem); err != nil {
		t.Fatal(err)
	}
}
