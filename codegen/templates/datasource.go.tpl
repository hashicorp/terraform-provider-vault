package {{ .DirName }}
// DO NOT EDIT
// This code is generated.

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
)

const {{ .PrivateFuncPrefix }}Endpoint = "{{ .Endpoint }}"

func {{ .ExportedFuncPrefix }}DataSource() *schema.Resource {
	return &schema.Resource{
		Read: {{ .PrivateFuncPrefix }}ReadDataSource,
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
				Elem:        &schema.Schema{Type: schema.TypeString},
				{{- end }}
				{{- if .Required }}
				Required:    true,
				{{- else }}
				Optional:    true,
				{{- end }}
				Description: "{{ .Description }}",
				Computed: true,
			},
			{{- end }}
		},
	}
}

func {{ .PrivateFuncPrefix }}ReadDataSource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string) + {{ .PrivateFuncPrefix }}Endpoint

	log.Printf("[DEBUG] Reading config %q", path)
	resp, err := client.Logical().Write(path, nil)
	if err != nil {
		return fmt.Errorf("error reading config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read config %q", path)

	if resp == nil {
		d.SetId("")
		return nil
	}
	d.SetId(path)

	{{- range .Parameters }}
	if err := d.Set("{{ .Name }}", resp.Data["{{ .Name }}"]); err != nil {
		return err
	}
	{{- end }}
	return nil
}
