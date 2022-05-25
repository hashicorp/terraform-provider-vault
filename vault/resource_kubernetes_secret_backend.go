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
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Path where Kubernetes engine is mounted",
			},
			"kubernetes_host": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Kubernetes API URL to connect to",
			},
			"service_account_jwt": {
				Type:     schema.TypeString,
				Optional: true,
				Description: "The JSON web token of the service account used by the " +
					"secret engine to manage Kubernetes roles. Defaults to the " +
					"local pod’s JWT if found",
			},
			"kubernetes_ca_cert": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				Description: "PEM encoded CA certificate to use by the secret engine to " +
					"verify the Kubernetes API server certificate. Defaults to the " +
					"local pod’s CA if found",
			},
			"disable_local_ca_jwt": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
				Description: "Disable defaulting to the local CA certificate and service " +
					"account JWT when running in a Kubernetes pod",
			},
			"default_lease_ttl": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Default lease TTL in seconds",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the Kubernetes mount",
			},
		},
	}
}

func kubernetesSecretBackendCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*api.Client)
	path := d.Get("path").(string)

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
	path := d.Get("path").(string)

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

	nonBooleanFields := []string{
		"service_account_jwt", "kubernetes_ca_cert",
	}

	// if kubernetes_host is set, it must always
	// be provided with a POST request to config endpoint
	if v, ok := d.GetOk("kubernetes_host"); ok {
		data["kubernetes_host"] = v.(string)
	}

	for _, k := range nonBooleanFields {
		if d.HasChange(k) {
			if v, ok := d.GetOk(k); ok {
				data[k] = v.(string)
			}
		}
	}

	if d.HasChange("disable_local_ca_jwt") {
		if v, ok := d.GetOkExists("disable_local_ca_jwt"); ok {
			data["disable_local_ca_jwt"] = v.(bool)
		}
	}

	if _, err := client.Logical().Write(fmt.Sprintf("%s/config", path), data); err != nil {
		return diag.Errorf("error writing Kubernetes config %q, err=%s", fmt.Sprintf("%s/config", path), err)
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
		"kubernetes_host", "service_account_jwt",
		"kubernetes_ca_cert", "disable_local_ca_jwt",
	}

	for _, k := range fields {
		if err := d.Set(k, resp.Data[k]); err != nil {
			return diag.Errorf("error setting state key %q on Kubernetes config, err=%s", k, err)
		}
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
