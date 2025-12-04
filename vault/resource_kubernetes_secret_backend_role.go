// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

var kubernetesSecretBackendFromPathRegex = regexp.MustCompile("^(.+)/roles/.+$")

const (
	fieldAllowedKubernetesNamespaces        = "allowed_kubernetes_namespaces"
	fieldAllowedKubernetesNamespaceSelector = "allowed_kubernetes_namespace_selector"
	fieldTokenMaxTTL                        = "token_max_ttl"
	fieldTokenDefaultTTL                    = "token_default_ttl"
	fieldServiceAccountName                 = "service_account_name"
	fieldKubernetesRoleName                 = "kubernetes_role_name"
	fieldKubernetesRoleType                 = "kubernetes_role_type"
	fieldGeneratedRoleRules                 = "generated_role_rules"
	fieldNameTemplate                       = "name_template"
	fieldExtraAnnotations                   = "extra_annotations"
	fieldExtraLabels                        = "extra_labels"
)

func kubernetesSecretBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: provider.MountCreateContextWrapper(kubernetesSecretBackendRoleCreateUpdate, provider.VaultVersion111),
		ReadContext:   provider.ReadContextWrapper(kubernetesSecretBackendRoleRead),
		UpdateContext: kubernetesSecretBackendRoleCreateUpdate,
		DeleteContext: kubernetesSecretBackendRoleDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			consts.FieldName: {
				Type:        schema.TypeString,
				Description: "The name of the role.",
				ForceNew:    true,
				Required:    true,
			},
			consts.FieldBackend: {
				Type:        schema.TypeString,
				Description: "The mount path for the Kubernetes secrets engine.",
				Required:    true,
				ForceNew:    true,
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			fieldAllowedKubernetesNamespaces: {
				Type: schema.TypeList,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "The list of Kubernetes namespaces this role can generate " +
					"credentials for. If set to '*' all namespaces are allowed. If set with" +
					"`allowed_kubernetes_namespace_selector`, the conditions are `OR`ed.",
				Optional: true,
			},
			fieldAllowedKubernetesNamespaceSelector: {
				Type: schema.TypeString,
				Description: "A label selector for Kubernetes namespaces in which credentials can be" +
					"generated. Accepts either a JSON or YAML object. The value should be of type" +
					"LabelSelector. If set with `allowed_kubernetes_namespace`, the conditions are `OR`ed.",
				Optional: true,
			},
			fieldTokenMaxTTL: {
				Type:        schema.TypeInt,
				Description: "The maximum TTL for generated Kubernetes tokens in seconds.",
				Optional:    true,
				Default:     0,
			},
			fieldTokenDefaultTTL: {
				Type:        schema.TypeInt,
				Description: "The default TTL for generated Kubernetes tokens in seconds.",
				Optional:    true,
				Default:     0,
			},
			fieldServiceAccountName: {
				Type: schema.TypeString,
				Description: "The pre-existing service account to generate tokens for. " +
					"Mutually exclusive with 'kubernetes_role_name' and 'generated_role_rules'. " +
					"If set, only a Kubernetes token will be created when credentials are requested.",
				Optional:     true,
				ExactlyOneOf: []string{fieldKubernetesRoleName, fieldGeneratedRoleRules},
			},
			fieldKubernetesRoleName: {
				Type: schema.TypeString,
				Description: "The pre-existing Role or ClusterRole to bind a generated " +
					"service account to. Mutually exclusive with 'service_account_name' and " +
					"'generated_role_rules'. If set, Kubernetes token, service account, and " +
					"role binding objects will be created when credentials are requested.",
				Optional: true,
			},
			fieldKubernetesRoleType: {
				Type:        schema.TypeString,
				Description: "Specifies whether the Kubernetes role is a Role or ClusterRole.",
				Optional:    true,
				Default:     "Role",
			},
			fieldGeneratedRoleRules: {
				Type: schema.TypeString,
				Description: "The Role or ClusterRole rules to use when generating a role. " +
					"Accepts either JSON or YAML formatted rules. Mutually exclusive with " +
					"'service_account_name' and 'kubernetes_role_name'. If set, the entire " +
					"chain of Kubernetes objects will be generated when credentials are requested.",
				Optional: true,
			},
			fieldNameTemplate: {
				Type: schema.TypeString,
				Description: "The name template to use when generating service accounts, " +
					"roles and role bindings. If unset, a default template is used.",
				Optional: true,
			},
			fieldExtraAnnotations: {
				Type:        schema.TypeMap,
				Description: "Additional annotations to apply to all generated Kubernetes objects.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			fieldExtraLabels: {
				Type:        schema.TypeMap,
				Description: "Additional labels to apply to all generated Kubernetes objects.",
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func kubernetesSecretBackendRoleCreateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	data := make(map[string]interface{})
	fields := []string{
		fieldAllowedKubernetesNamespaces,
		fieldAllowedKubernetesNamespaceSelector,
		fieldTokenMaxTTL,
		fieldTokenDefaultTTL,
		fieldServiceAccountName,
		fieldKubernetesRoleName,
		fieldKubernetesRoleType,
		fieldGeneratedRoleRules,
		fieldNameTemplate,
		fieldExtraAnnotations,
		fieldExtraLabels,
	}
	for _, k := range fields {
		if k == fieldAllowedKubernetesNamespaceSelector && !provider.IsAPISupported(meta, provider.VaultVersion112) {
			continue
		}
		if d.HasChange(k) {
			data[k] = d.Get(k)
		}
	}

	name := d.Get(consts.FieldName).(string)
	backend := d.Get(consts.FieldBackend).(string)
	rolePath := kubernetesSecretBackendRolePath(backend, name)
	if _, err := client.Logical().Write(rolePath, data); err != nil {
		return diag.Errorf(`error writing Kubernetes backend role %q, err=%s`,
			rolePath, err)
	}

	d.SetId(rolePath)
	return kubernetesSecretBackendRoleRead(ctx, d, meta)
}

func kubernetesSecretBackendRoleRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	path := d.Id()
	resp, err := client.Logical().Read(path)
	if err != nil {
		return diag.Errorf("error reading Kubernetes backend role at %s: err=%s",
			path, err)
	}
	if resp == nil {
		log.Printf("[WARN] Kubernetes backend role not found, removing from state")
		d.SetId("")
		return nil
	}

	backend, err := kubernetesSecretBackendFromPath(path)
	if err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set(consts.FieldBackend, backend); err != nil {
		return diag.FromErr(err)
	}

	fields := []string{
		consts.FieldName,
		fieldAllowedKubernetesNamespaces,
		fieldAllowedKubernetesNamespaceSelector,
		fieldTokenMaxTTL,
		fieldTokenDefaultTTL,
		fieldServiceAccountName,
		fieldKubernetesRoleName,
		fieldKubernetesRoleType,
		fieldGeneratedRoleRules,
		fieldNameTemplate,
		fieldExtraAnnotations,
		fieldExtraLabels,
	}
	for _, k := range fields {
		if k == fieldAllowedKubernetesNamespaceSelector && !provider.IsAPISupported(meta, provider.VaultVersion112) {
			continue
		}
		if err := d.Set(k, resp.Data[k]); err != nil {
			return diag.Errorf("error setting state key %q on Kubernetes backend role, err=%s",
				k, err)
		}
	}

	return nil
}

func kubernetesSecretBackendRoleDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client, err := provider.GetClient(d, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	path := d.Id()
	if _, err := client.Logical().Delete(path); err != nil {
		return diag.Errorf("error deleting Kubernetes backend role at %q: %s", path, err)
	}

	return nil
}

func kubernetesSecretBackendRolePath(backend, name string) string {
	return strings.Trim(backend, "/") + "/roles/" + name
}

func kubernetesSecretBackendFromPath(path string) (string, error) {
	if !kubernetesSecretBackendFromPathRegex.MatchString(path) {
		return "", fmt.Errorf("no backend found")
	}
	res := kubernetesSecretBackendFromPathRegex.FindStringSubmatch(path)
	if len(res) != 2 {
		return "", fmt.Errorf("unexpected number of matches (%d) for backend", len(res))
	}
	return res[1], nil
}
