package vault

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/util"
)

const (
	FieldPath              = "path"
	FieldKubernetesHost    = "kubernetes_host"
	FieldServiceAccountJWT = "service_account_jwt"
	FieldKubernetesCACert  = "kubernetes_ca_cert"
	FieldDisableLocalCAJWT = "disable_local_ca_jwt"
	FieldDefaultLeaseTTL   = "default_lease_ttl"
	FieldDescription       = "description"
)

func kubernetesSecretBackendResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: kubernetesSecretBackendCreate,
		ReadContext:   kubernetesSecretBackendRead,
		UpdateContext: kubernetesSecretBackendUpdate,
		DeleteContext: kubernetesSecretBackendDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			FieldPath: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Path where Kubernetes engine is mounted",
			},
			FieldKubernetesHost: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Kubernetes API URL to connect to",
			},
			FieldServiceAccountJWT: {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The JSON web token of the service account used by the " +
					"secret engine to manage Kubernetes roles. Defaults to the " +
					"local pod’s JWT if found",
			},
			FieldKubernetesCACert: {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				Description: "PEM encoded CA certificate to use by the secret engine to " +
					"verify the Kubernetes API server certificate. Defaults to the " +
					"local pod’s CA if found",
			},
			FieldDisableLocalCAJWT: {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
				Description: "Disable defaulting to the local CA certificate and service " +
					"account JWT when running in a Kubernetes pod",
			},
			FieldDefaultLeaseTTL: {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Default lease TTL in seconds",
			},
			FieldDescription: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the Kubernetes mount",
			},
		},
	}
}

func kubernetesSecretBackendCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*api.Client)
	path := d.Get(FieldPath).(string)

	log.Printf("[DEBUG] Mounting Kubernetes backend at %q", path)
	if err := client.Sys().Mount(path, &api.MountInput{
		Type:        "kubernetes",
		Description: d.Get("description").(string),
		Config: api.MountConfigInput{
			DefaultLeaseTTL: fmt.Sprintf("%ds", d.Get("default_lease_ttl").(int)),
		},
	}); err != nil {
		return diag.Errorf("error mounting to %q, err=%s", path, err)
	}

	d.SetId(path)

	return kubernetesSecretBackendUpdate(ctx, d, meta)
}

func kubernetesSecretBackendUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*api.Client)
	path := d.Get(FieldPath).(string)

	log.Printf("[DEBUG] Updating mount %s in Vault", path)

	if d.HasChange("default_lease_ttl") || d.HasChange("description") {
		tune := api.MountConfigInput{}
		tune.DefaultLeaseTTL = fmt.Sprintf("%ds", d.Get("default_lease_ttl"))
		description := d.Get("description").(string)
		tune.Description = &description

		log.Printf("[DEBUG] Updating mount for %q", path)
		err := client.Sys().TuneMount(path, tune)
		if err != nil {
			return diag.Errorf("error updating mount for %q, err=%s", path, err)
		}
		log.Printf("[DEBUG] Updated mount for %q", path)
	}

	data := map[string]interface{}{}

	fields := []string{
		FieldServiceAccountJWT,
		FieldKubernetesCACert,
		FieldDisableLocalCAJWT,
		FieldKubernetesHost,
	}

	for _, k := range fields {
		if d.HasChange(k) {
			data[k] = d.Get(k)
		}
	}

	configPath := fmt.Sprintf("%s/config", path)
	if _, err := client.Logical().Write(configPath, data); err != nil {
		return diag.Errorf(`error writing Kubernetes config %q, err=%s`, configPath, err)
	}

	return kubernetesSecretBackendRead(ctx, d, meta)
}

func kubernetesSecretBackendRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*api.Client)
	path := d.Id()

	log.Printf("[DEBUG] Reading Kubernetes config at %s/config", path)
	resp, err := client.Logical().Read(path + "/config")
	if err != nil {
		return diag.Errorf("error reading Kubernetes config at %s/config: err=%s", path, err)
	}

	if resp == nil {
		log.Printf("[WARN] Kubernetes config not found, removing from state")
		d.SetId("")

		return nil
	}

	fields := []string{
		FieldKubernetesHost,
		FieldServiceAccountJWT,
		FieldKubernetesCACert,
		FieldDisableLocalCAJWT,
	}

	for _, k := range fields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return diag.Errorf("error setting state key %q on Kubernetes config, err=%s", k, err)
		}
	}

	if err := d.Set(FieldPath, d.Get(FieldPath)); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set(FieldDescription, d.Get(FieldDescription)); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func kubernetesSecretBackendDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*api.Client)
	path := d.Id()
	log.Printf("[DEBUG] Unmounting Kubernetes backend %q", path)

	if err := client.Sys().Unmount(path); err != nil {
		if util.Is404(err) {
			log.Printf("[WARN] %q not found, removing from state", path)
			d.SetId("")

		}

		return diag.Errorf("error unmounting Kubernetes backend from %q, err=%s", path, err)
	}

	log.Printf("[DEBUG] Unmounted Kubernetes backend at %q", path)

	return nil
}
