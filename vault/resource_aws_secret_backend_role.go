package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

func awsSecretBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		Create: awsSecretBackendRoleWrite,
		Read:   awsSecretBackendRoleRead,
		Update: awsSecretBackendRoleWrite,
		Delete: awsSecretBackendRoleDelete,
		Exists: awsSecretBackendRoleExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Unique name for the role.",
			},
			"backend": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The path of the AWS Secret Backend the role belongs to.",
			},
			"policy_arn": {
				Type:          schema.TypeString,
				Optional:      true,
				ConflictsWith: []string{"policy"},
				Description:   "ARN for an existing IAM policy the role should use.",
			},
			"policy": {
				Type:             schema.TypeString,
				Optional:         true,
				ConflictsWith:    []string{"policy_arn"},
				Description:      "IAM policy the role should use in JSON format.",
				DiffSuppressFunc: jsonDiffSuppress,
			},
		},
	}
}

func awsSecretBackendRoleWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)
	policyARN := d.Get("policy_arn").(string)
	policy := d.Get("policy").(string)

	if policy == "" && policyARN == "" {
		return fmt.Errorf("Either policy or policy_arn must be set.")
	}

	data := map[string]interface{}{}
	if policy != "" {
		data["policy"] = policy
	}
	if policyARN != "" {
		data["arn"] = policyARN
	}
	log.Printf("[DEBUG] Creating role %q on AWS backend %q", name, backend)
	_, err := client.Logical().Write(backend+"/roles/"+name, data)
	if err != nil {
		return fmt.Errorf("Error creating role %q for backend %q: %s", name, backend, err)
	}
	log.Printf("[DEBUG] Created role %q on AWS backend %q", name, backend)

	d.SetId(backend + "/roles/" + name)
	return awsSecretBackendRoleRead(d, meta)
}

func awsSecretBackendRoleRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	pathPieces := strings.Split(path, "/")
	if len(pathPieces) < 3 || pathPieces[len(pathPieces)-2] != "roles" {
		return fmt.Errorf("Invalid id %q; must be {backend}/roles/{name}", path)
	}

	log.Printf("[DEBUG] Reading role from %q", path)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("Error reading role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read role from %q", path)
	if secret == nil {
		log.Printf("[WARN] Role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}
	d.Set("policy", secret.Data["policy"])
	d.Set("policy_arn", secret.Data["arn"])
	d.Set("backend", strings.Join(pathPieces[:len(pathPieces)-2], "/"))
	d.Set("name", pathPieces[len(pathPieces)-1])
	return nil
}

func awsSecretBackendRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Deleting role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("Error deleting role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Deleted role %q", path)
	return nil
}

func awsSecretBackendRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Checking if %q exists", path)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("Error checking if %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if %q exists", path)
	return secret != nil, nil
}
