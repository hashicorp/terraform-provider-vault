package {{ .DirName }}

// DO NOT EDIT
// This code is generated.

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/terraform-provider-vault/util"
)

const {{ .LowerCaseDifferentiator }}Endpoint = "{{ .Endpoint }}"

func {{ .UpperCaseDifferentiator }}DataSource() *schema.Resource {
	return &schema.Resource{
        Read: read{{ .UpperCaseDifferentiator }}Resource,
		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Path to backend from which to retrieve data.",
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			{{- range .Parameters }}
			"{{ .Name }}": {
				{{- if (eq .Schema.Type "string") }}
				Type:        schema.TypeString,
				{{- end }}
				{{- if (eq .Schema.Type "boolean") }}
				Type:        schema.TypeBool,
				{{- end }}
				{{- if (eq .Schema.Type "integer") }}
				Type:        schema.TypeInt,
				{{- end }}
				{{- if (eq .Schema.Type "array") }}
                Type:        schema.TypeList,
                {{- if (eq .Schema.Items.Type "string") }}
                Elem:        &schema.Schema{Type: schema.TypeString},
                {{- end }} {{/* end if item type string */}}
                {{- if (eq .Schema.Items.Type "object") }}
                Elem:        &schema.Schema{Type: schema.TypeMap},
                {{- end }} {{/* end if item type object */}}
                {{- end }} {{/* end if array */}}
				{{- if .Required }}
				Required:    true,
				{{- else }}
				Optional:    true,
				{{- end }}
				{{- if .IsPathParam }}
                ForceNew:    true,
                {{- end }}
                {{- if .Computed }}
                Computed:    true,
                {{- end }}
				Description: "{{ .Description }}",
			},
			{{- end }}
		},
	}
}

func read{{ .UpperCaseDifferentiator }}Resource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
    path := d.Get("path").(string)
    vaultPath := util.ParsePath(path, {{ .LowerCaseDifferentiator }}Endpoint, d)
    log.Printf("[DEBUG] Writing %q", vaultPath)

    data := make(map[string]interface{})
    {{- range .Parameters }}
    {{- if not .Computed }}
    if val, ok := d.GetOkExists("{{ .Name }}"); ok {
        data["{{ .Name }}"] = val
    }
    {{- end }}
    {{- end }}
    log.Printf("[DEBUG] Writing %q", vaultPath)
    resp, err := client.Logical().Write(vaultPath, data)
    if err != nil {
        return fmt.Errorf("error writing %q: %s", vaultPath, err)
    }
    if resp == nil {
        d.SetId("")
        return nil
    }
    d.SetId(vaultPath)

    {{- range .Parameters }}
    {{- if .Computed }}
    if err := d.Set("{{ .Name }}", resp.Data["{{ .Name }}"]); err != nil {
        return err
    }
    {{- end }}
    {{- end }}
    return nil
}
