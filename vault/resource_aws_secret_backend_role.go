package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
	"github.com/terraform-providers/terraform-provider-vault/util"
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
			"policy_arns": {
				Type:          schema.TypeList,
				Optional:      true,
				ConflictsWith: []string{"policy", "policy_arn", "role_arns"},
				Description:   "ARN for an existing IAM policy the role should use.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"policy_arn": {
				Type:          schema.TypeString,
				Optional:      true,
				ConflictsWith: []string{"policy_document", "policy", "policy_arns", "role_arns"},
				Description:   "ARN for an existing IAM policy the role should use.",
				Deprecated:    `Use "policy_arns".`,
			},
			"policy_document": {
				Type:             schema.TypeString,
				Optional:         true,
				ConflictsWith:    []string{"policy_arn", "policy", "role_arns"},
				Description:      "IAM policy the role should use in JSON format.",
				DiffSuppressFunc: util.JsonDiffSuppress,
			},
			"policy": {
				Type:             schema.TypeString,
				Optional:         true,
				ConflictsWith:    []string{"policy_arns", "policy_arn", "policy_document", "role_arns"},
				Description:      "IAM policy the role should use in JSON format.",
				DiffSuppressFunc: util.JsonDiffSuppress,
				Deprecated:       `Use "policy_document".`,
			},
			"credential_type": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Role credential type.",
			},
			"role_arns": {
				Type: schema.TypeList,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional:      true,
				ForceNew:      true,
				ConflictsWith: []string{"policy", "policy_arn", "policy_arns", "policy_document"},
				Description:   "ARNs of AWS roles allowed to be assumed. Only valid when credential_type is 'assumed_role'",
			},
		},
	}
}

func awsSecretBackendRoleWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)

	policyARNsIfc, ok := d.GetOk("policy_arns")
	var policyARNs []string
	if !ok {
		policyARN := d.Get("policy_arn").(string)
		if policyARN != "" {
			policyARNs = append(policyARNs, policyARN)
		}
	}
	for _, arnIfc := range policyARNsIfc.([]interface{}) {
		policyARNs = append(policyARNs, arnIfc.(string))
	}

	policy, ok := d.GetOk("policy_document")
	if !ok {
		policy = d.Get("policy")
	}

	var roleARNs []string
	roleARNsIfc := d.Get("role_arns")
	for _, roleIfc := range roleARNsIfc.([]interface{}) {
		roleARNs = append(roleARNs, roleIfc.(string))
	}

	if policy == "" && len(policyARNs) == 0 && len(roleARNs) == 0 {
		return fmt.Errorf("either policy, policy_arns, or role_arns must be set")
	}

	data := map[string]interface{}{
		"credential_type": d.Get("credential_type").(string),
	}
	if policy != "" {
		data["policy_document"] = policy
	}
	if len(policyARNs) != 0 {
		data["policy_arns"] = policyARNs
	}
	if len(roleARNs) != 0 {
		data["role_arns"] = roleARNs
	}

	log.Printf("[DEBUG] Creating role %q on AWS backend %q", name, backend)
	_, err := client.Logical().Write(backend+"/roles/"+name, data)
	if err != nil {
		return fmt.Errorf("error creating role %q for backend %q: %s", name, backend, err)
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
		return fmt.Errorf("invalid id %q; must be {backend}/roles/{name}", path)
	}

	log.Printf("[DEBUG] Reading role from %q", path)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("error reading role %q: %s", path, err)
	}
	log.Printf("[DEBUG] Read role from %q", path)
	if secret == nil {
		log.Printf("[WARN] Role %q not found, removing from state", path)
		d.SetId("")
		return nil
	}

	if _, ok := d.GetOk("policy_document"); ok {
		d.Set("policy_document", secret.Data["policy_document"])
	} else if _, ok := d.GetOk("policy"); ok {
		d.Set("policy", secret.Data["policy_document"])
	} else if v, ok := secret.Data["policy_document"]; ok {
		d.Set("policy_document", v)
	}

	if _, ok := d.GetOk("policy_arns"); ok {
		d.Set("policy_arns", secret.Data["policy_arns"])
	} else if _, ok := d.GetOk("policy_arn"); ok {
		d.Set("policy_arn", secret.Data["policy_arns"])
	} else if v, ok := secret.Data["policy_arns"]; ok {
		d.Set("policy_arns", v)
	}

	d.Set("credential_type", secret.Data["credential_type"])
	d.Set("role_arns", secret.Data["role_arns"])
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
		return fmt.Errorf("error deleting role %q: %s", path, err)
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
		return true, fmt.Errorf("error checking if %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if %q exists", path)
	return secret != nil, nil
}
