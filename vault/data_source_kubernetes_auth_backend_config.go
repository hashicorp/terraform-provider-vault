// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/consts"
	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func kubernetesAuthBackendConfigDataSource() *schema.Resource {
	return &schema.Resource{
		Read: provider.ReadWrapper(kubernetesAuthBackendConfigDataSourceRead),
		Schema: map[string]*schema.Schema{
			"backend": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Unique name of the kubernetes backend to configure.",
				ForceNew:    true,
				Default:     "kubernetes",
				// standardise on no beginning or trailing slashes
				StateFunc: func(v interface{}) string {
					return strings.Trim(v.(string), "/")
				},
			},
			consts.FieldKubernetesHost: {
				Type:        schema.TypeString,
				Computed:    true,
				Optional:    true,
				Description: "Host must be a host string, a host:port pair, or a URL to the base of the Kubernetes API server.",
			},
			consts.FieldKubernetesCACert: {
				Type:        schema.TypeString,
				Description: "PEM encoded CA cert for use by the TLS client used to talk with the Kubernetes API.",
				Computed:    true,
				Optional:    true,
			},
			consts.FieldPEMKeys: {
				Type:        schema.TypeList,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Computed:    true,
				Description: "Optional list of PEM-formatted public keys or certificates used to verify the signatures of Kubernetes service account JWTs. If a certificate is given, its public key will be extracted. Not every installation of Kubernetes exposes these keys.",
				Optional:    true,
			},
			consts.FieldIssuer: {
				Type:        schema.TypeString,
				Computed:    true,
				Optional:    true,
				Description: "Optional JWT issuer. If no issuer is specified, kubernetes.io/serviceaccount will be used as the default issuer.",
			},
			consts.FieldDisableISSValidation: {
				Type:        schema.TypeBool,
				Computed:    true,
				Optional:    true,
				Description: "Optional disable JWT issuer validation. Allows to skip ISS validation.",
			},
			consts.FieldDisableLocalCAJWT: {
				Type:        schema.TypeBool,
				Computed:    true,
				Optional:    true,
				Description: "Optional disable defaulting to the local CA cert and service account JWT when running in a Kubernetes pod.",
			},
		},
	}
}

func kubernetesAuthBackendConfigDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := kubernetesAuthBackendConfigPath(d.Get("backend").(string))

	log.Printf("[DEBUG] Reading Kubernetes auth backend config %q", path)
	resp, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading Kubernetes auth backend config %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read Kubernetes auth backend config %q", path)

	if resp == nil {
		d.SetId("")
		return nil
	}
	d.SetId(path)
	d.Set(consts.FieldKubernetesCACert, resp.Data[consts.FieldKubernetesCACert])
	d.Set(consts.FieldKubernetesHost, resp.Data[consts.FieldKubernetesHost])

	iPemKeys := resp.Data[consts.FieldPEMKeys].([]interface{})
	pemKeys := make([]string, 0, len(iPemKeys))

	for _, iPemKey := range iPemKeys {
		pemKeys = append(pemKeys, iPemKey.(string))
	}

	d.Set(consts.FieldPEMKeys, pemKeys)
	d.Set(consts.FieldIssuer, resp.Data[consts.FieldIssuer])
	d.Set(consts.FieldDisableISSValidation, resp.Data[consts.FieldDisableISSValidation])
	d.Set(consts.FieldDisableLocalCAJWT, resp.Data[consts.FieldDisableLocalCAJWT])

	return nil
}
