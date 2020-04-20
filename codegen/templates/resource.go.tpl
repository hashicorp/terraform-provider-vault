package {{ .DirName }}
// DO NOT EDIT
// This code is generated.

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/vault/api"
	{{- if .SupportsWrite }}
	"github.com/terraform-providers/terraform-provider-vault/util"
	{{- end }}
)

{{- if .SupportsWrite }}
const {{ .PrivateFuncPrefix }}Endpoint = "{{ .Endpoint }}"
{{- else }}
// This resource supports "{{ .Endpoint }}".
{{ end }}

func {{ .ExportedFuncPrefix }}Resource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"path": {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: "Path to backend to configure.",
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
			{{- if .Schema.DisplayAttrs.Sensitive }}
			Sensitive:   true,
			{{- end }}
			Description: "{{ .Description }}",
		},
		{{- end }}
	}
	return &schema.Resource{
		{{- if .SupportsWrite }}
		Create: {{ .PrivateFuncPrefix }}CreateResource,
		Update: {{ .PrivateFuncPrefix }}UpdateResource,
		{{- end }}
		{{- if .SupportsRead }}
		Read:   {{ .PrivateFuncPrefix }}ReadResource,
		Exists: {{ .PrivateFuncPrefix }}ResourceExists,
		{{- end }}
		{{- if .SupportsDelete }}
		Delete: {{ .PrivateFuncPrefix }}DeleteResource,
		{{- end }}
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: fields,
	}
}

{{- if .SupportsWrite }}
func {{ .PrivateFuncPrefix }}CreateResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("path").(string)

	data := map[string]interface{}{}
	{{- range .Parameters }}
	if v, ok := d.GetOkExists("{{ .Name }}"); ok {
		data["{{ .Name }}"] = v
	}
	{{- end }}

	path := util.ReplacePathParameters(backend + {{ .PrivateFuncPrefix }}Endpoint, d)
	log.Printf("[DEBUG] Writing %q", path)
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing %q: %s", path, err)
	}
	d.SetId(path)
	log.Printf("[DEBUG] Wrote %q", path)
	return {{ .PrivateFuncPrefix }}ReadResource(d, meta)
}
{{ end }}

{{- if .SupportsRead }}
func {{ .PrivateFuncPrefix }}ReadResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Reading %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read %q", path)
	if resp == nil {
		log.Printf("[WARN] %q not found, removing from state", path)
		d.SetId("")
		return nil
	}
	{{- range .Parameters }}
	if err := d.Set("{{ .Name }}", resp.Data["{{ .Name }}"]); err != nil {
		return fmt.Errorf("error setting state key '{{ .Name }}': %s", err)
	}
	{{- end }}
	return nil
}
{{ end }}

{{- if .SupportsWrite }}
func {{ .PrivateFuncPrefix }}UpdateResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Updating %q", path)

	data := map[string]interface{}{}
	{{- range .Parameters }}
	if d.HasChange("{{ .Name }}") {
		data["{{ .Name }}"] = d.Get("{{ .Name }}")
	}
	{{- end }}
	defer func() {
		d.SetId(path)
	}()
	_, err := client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("error updating template auth backend role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Updated %q", path)
	return {{ .PrivateFuncPrefix }}ReadResource(d, meta)
}
{{ end }}

{{- if .SupportsDelete }}
func {{ .PrivateFuncPrefix }}DeleteResource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Deleting %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil && !util.Is404(err) {
		return fmt.Errorf("error deleting %q", path)
	} else if err != nil {
		log.Printf("[DEBUG] %q not found, removing from state", path)
		d.SetId("")
		return nil
	}
	log.Printf("[DEBUG] Deleted template auth backend role %q", path)
	return nil
}
{{ end }}

{{- if .SupportsRead }}
func {{ .PrivateFuncPrefix }}ResourceExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Checking if %q exists", path)

	resp, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if %q exists", path)
	return resp != nil, nil
}
{{- end }}
