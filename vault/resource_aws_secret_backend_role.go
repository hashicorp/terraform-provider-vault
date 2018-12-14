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
			"policy_arn": {
				Type:          schema.TypeString,
				Optional:      true,
				ConflictsWith: []string{"policy_arns", "role_arns", "policy", "policy_document"},
				Description:   "**Deprecated** IAM policy the role should use in JSON format.",
				Deprecated:    "Use policy_arns or role_arns for iam_user or assumed_role respectively",
			},
			"policy_arns": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				ConflictsWith: []string{"policy", "role_arns", "policy_arn", "policy_document"},
				Description:   "ARNs for existing IAM policies the role should use.",
			},
			"role_arns": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				ConflictsWith: []string{"policy", "policy_arns", "policy_arn", "policy_document"},
				Description:   "ARNs for existing roles that should be used.",
			},
			"policy": {
				Type:             schema.TypeString,
				Optional:         true,
				ConflictsWith:    []string{"policy_arns", "role_arns", "policy_arn", "credential_type", "policy_document"},
				Description:      "**Deprecated** IAM policy the role should use in JSON format.",
				Deprecated:       "Use policy_document with credential_type",
				DiffSuppressFunc: util.JsonDiffSuppress,
			},
			"credential_type": {
				Type:          schema.TypeString,
				Optional:      true,
				ConflictsWith: []string{"policy"},
				Description:   "Specifies the type of credential to be used when retrieving credentials from the role. Must be one of iam_user, assumed_role, or federation_token.",
			},
			"policy_document": {
				Type:             schema.TypeString,
				Optional:         true,
				ConflictsWith:    []string{"policy_arns", "role_arns", "policy_arn", "policy"},
				Description:      "IAM policy the role should use in JSON format.",
				DiffSuppressFunc: util.JsonDiffSuppress,
			},
		},
	}
}

func awsSecretBackendRoleWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)
	credential_type := d.Get("credential_type").(string)

	data := map[string]interface{}{}
	attrSet := false

	if policy, ok := d.GetOkExists("policy"); ok {
		data["policy"] = policy.(string)
		credential_type = ""
		attrSet = true
	} else if policy_document, ok := d.GetOk("policy_document"); ok {
		data["policy_document"] = policy_document.(string)
		if credential_type == "" {
			return fmt.Errorf("You need to supply a credential_type of iam_user or assumed_role")
		}
		attrSet = true
	}
	if ARN, ok := d.GetOk("policy_arn"); ok {
		data["arn"] = ARN.(string)
		credential_type = ""
		attrSet = true
	} else if policyARNs, ok := d.GetOk("policy_arns"); ok {
		data["policy_arns"] = util.ToStringArray(policyARNs.(*schema.Set).List())
		if credential_type == "" {
			credential_type = "iam_user"
		}
		attrSet = true
	}
	if roleARNs, ok := d.GetOk("role_arns"); ok {
		data["role_arns"] = util.ToStringArray(roleARNs.(*schema.Set).List())
		if credential_type == "" {
			credential_type = "assumed_role"
		}
		attrSet = true
	}
	if !attrSet {
		return fmt.Errorf("either policy, policy_arn, policy_arns, policy_document or role_arns must be set.")
	}

	if credential_type != "" {
		data["credential_type"] = credential_type
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

	credential_set := true // Deprecated `policy_arn` and `policy` can't use credential_type
	var ok bool

	// 0.11.0 Uses version policy_document over deprecated policy
	if _, ok = d.GetOk("policy"); ok {
		d.Set("policy", secret.Data["policy_document"])
		credential_set = false
	} else {
		d.Set("policy_document", secret.Data["policy_document"])
	}

	// 0.11.0 Uses version policy_arns over deprecated policy_arn
	if _, ok = d.GetOk("policy_arn"); ok {
		if secret.Data["policy_arns"] != nil {
			d.Set("policy_arn", util.ToStringArray(secret.Data["policy_arns"].([]interface{}))[0])
		}
		credential_set = false
	} else {
		d.Set("policy_arns", secret.Data["policy_arns"])
	}

	// 0.11.0 Uses  role_arns and policy_arns over old `arn` which was implemented with `policy_arn`
	d.Set("role_arns", secret.Data["role_arns"])

	if secret.Data["credential_type"] != nil && credential_set {
		// Credential_type is single value, but vault returns multi-value credential_types. Sometimes adding federation_token
		d.Set("credential_type", util.ToStringArray(secret.Data["credential_types"].([]interface{}))[0])
	}

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
