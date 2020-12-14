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

{{- if or .SupportsRead .SupportsWrite }}
const {{ .LowerCaseDifferentiator }}Endpoint = "{{ .Endpoint }}"
{{- else }}
// This resource supports "{{ .Endpoint }}".
{{ end }}

func {{ .UpperCaseDifferentiator }}Resource() *schema.Resource {
	fields := map[string]*schema.Schema{
		"path": {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: `The mount path for a back-end, for example, the path given in "$ vault auth enable -path=my-aws aws".`,
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
			{{- if .Computed }}
            Computed:    true,
            {{- end }}
			{{- if .Schema.DisplayAttrs.Sensitive }}
			Sensitive:   true,
			{{- end }}
			Description: `{{ .Description }}`,
			{{- if .IsPathParam }}
			ForceNew: true,
			{{- end}}
		},
		{{- end }}
	}
	return &schema.Resource{
		{{- if .SupportsWrite }}
		Create: create{{ .UpperCaseDifferentiator }}Resource,
		Update: update{{ .UpperCaseDifferentiator }}Resource,
		{{- end }}
		{{- if .SupportsRead }}
		Read:   read{{ .UpperCaseDifferentiator }}Resource,
		Exists: resource{{ .UpperCaseDifferentiator }}Exists,
		{{- end }}
		{{- if or .SupportsDelete .SupportsWrite  }}
		Delete: delete{{ .UpperCaseDifferentiator }}Resource,
		{{- end }}
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: fields,
	}
}

{{- if .SupportsWrite }}
func create{{ .UpperCaseDifferentiator }}Resource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	path := d.Get("path").(string)
	vaultPath := util.ParsePath(path, {{ .LowerCaseDifferentiator }}Endpoint, d)
	log.Printf("[DEBUG] Creating %q", vaultPath)

	data := map[string]interface{}{}
	{{- range .Parameters }}
	{{- if .IsPathParam}}
	  {{- if not .Computed }}
    data["{{ .Name }}"] = d.Get("{{ .Name }}")
	  {{- end }}
	{{- end }}
	{{- if not .IsPathParam }}
	  {{- if not .Computed }}
    if v, ok := d.GetOkExists("{{ .Name }}"); ok {
        data["{{ .Name }}"] = v
    }
	  {{- end }}
	{{- end }}
	{{- end }}

	log.Printf("[DEBUG] Writing %q", vaultPath)
	if _, err := client.Logical().Write(vaultPath, data); err != nil {
		return fmt.Errorf("error writing %q: %s", vaultPath, err)
	}
	d.SetId(vaultPath)
	log.Printf("[DEBUG] Wrote %q", vaultPath)
	return read{{ .UpperCaseDifferentiator }}Resource(d, meta)
}
{{ end }}

{{- if .SupportsRead }}
func read{{ .UpperCaseDifferentiator }}Resource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	vaultPath := d.Id()
	log.Printf("[DEBUG] Reading %q", vaultPath)

	resp, err := client.Logical().Read(vaultPath)
	if err != nil {
		return fmt.Errorf("error reading %q: %s", vaultPath, err)
	}
	log.Printf("[DEBUG] Read %q", vaultPath)
	if resp == nil {
		log.Printf("[WARN] %q not found, removing from state", vaultPath)
		d.SetId("")
		return nil
	}
	pathParams, err := util.PathParameters({{ .LowerCaseDifferentiator }}Endpoint, vaultPath)
    if err != nil {
        return err
    }
    for paramName, paramVal := range pathParams {
        if err := d.Set(paramName, paramVal); err != nil {
            return fmt.Errorf("error setting state %q, %q: %s", paramName, paramVal, err)
        }
    }
	{{- range .Parameters }}
	{{- if not .IsPathParam }}
	if val, ok := resp.Data["{{ .Name }}"]; ok {
        if err := d.Set("{{ .Name }}", val); err != nil {
            return fmt.Errorf("error setting state key '{{ .Name }}': %s", err)
        }
    }
    {{- end }}
	{{- end }}
	return nil
}
{{ end }}

{{- if .SupportsWrite }}
func update{{ .UpperCaseDifferentiator }}Resource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	vaultPath := d.Id()
	log.Printf("[DEBUG] Updating %q", vaultPath)

	data := map[string]interface{}{}
	{{- range .Parameters }}
	{{- if not .IsPathParam }}
	  {{- if not .Computed }}
	if raw, ok := d.GetOk("{{ .Name }}"); ok {
		data["{{ .Name }}"] = raw
	}
	  {{- end }}
	{{- end }}
	{{- end }}
	if _, err := client.Logical().Write(vaultPath, data); err != nil {
		return fmt.Errorf("error updating template auth backend role %q: %s", vaultPath, err)
	}
	log.Printf("[DEBUG] Updated %q", vaultPath)
	return read{{ .UpperCaseDifferentiator }}Resource(d, meta)
}
{{ end }}

{{- if .SupportsDelete }}
func delete{{ .UpperCaseDifferentiator }}Resource(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	vaultPath := d.Id()
	log.Printf("[DEBUG] Deleting %q", vaultPath)

	if _, err := client.Logical().Delete(vaultPath); err != nil && !util.Is404(err) {
		return fmt.Errorf("error deleting %q: %s", vaultPath, err)
	} else if err != nil {
		log.Printf("[DEBUG] %q not found, removing from state", vaultPath)
		d.SetId("")
		return nil
	}
	log.Printf("[DEBUG] Deleted template auth backend role %q", vaultPath)
	return nil
}
{{ else if .SupportsWrite }}
func delete{{ .UpperCaseDifferentiator }}Resource(_ *schema.ResourceData, _ interface{}) error {
	// Terraform requires the delete is implemented whenever create is implemented,
	// but this endpoint doesn't support delete. Thus, we've simply stubbed out delete
	// here.
	return nil
}
{{ end }}

{{- if .SupportsRead }}
func resource{{ .UpperCaseDifferentiator }}Exists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)
	vaultPath := d.Id()
	log.Printf("[DEBUG] Checking if %q exists", vaultPath)

	resp, err := client.Logical().Read(vaultPath)
	if err != nil {
		return true, fmt.Errorf("error checking if %q exists: %s", vaultPath, err)
	}
	log.Printf("[DEBUG] Checked if %q exists", vaultPath)
	return resp != nil, nil
}
{{- end }}
