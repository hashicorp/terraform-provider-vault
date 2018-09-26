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
			"credential_type": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Specifies the type of credential to be used when retrieving credentials from the role.",
				// DefaultFunc: ??,
			},
			"role_arns": {
				Type: schema.TypeList,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional:      true,
				ForceNew:      true,
				ConflictsWith: []string{"policy", "policy_arn", "policy_arns", "policy_document"},
				Description:   "Specifies the ARNs of the AWS roles this Vault role is allowed to assume.",
			},
			"policy_arns": {
				Type: schema.TypeList,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Optional:      true,
				ForceNew:      true,
				ConflictsWith: []string{"policy", "policy_arn", "role_arns"},
				Description:   "Specifies the ARNs of the AWS managed policies to be attached to IAM users when they are requested.",
			},
			"policy_document": {
				Type:             schema.TypeString,
				Optional:         true,
				ForceNew:         true,
				ConflictsWith:    []string{"policy", "policy_arn", "role_arns"},
				Description:      "Specifies the ARNs of the AWS managed policies to be attached to IAM users when they are requested.",
				DiffSuppressFunc: jsonDiffSuppress,
			},
			"policy_arn": {
				Type:          schema.TypeString,
				Optional:      true,
				ConflictsWith: []string{"policy", "credential_type", "role_arns", "policy_arns", "policy_document"},
				Description:   "ARN for an existing IAM policy the role should use.",
				Deprecated:    "Deprecated from Vault 0.11.",
			},
			"policy": {
				Type:             schema.TypeString,
				Optional:         true,
				ConflictsWith:    []string{"policy_arn", "credential_type", "role_arns", "policy_arns", "policy_document"},
				Description:      "IAM policy the role should use in JSON format.",
				Deprecated:       "Deprecated from Vault 0.11.",
				DiffSuppressFunc: jsonDiffSuppress,
			},
		},
	}
}

func awsSecretBackendRoleWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)

	credentialType := d.Get("credential_type").(string)
	roleARNs := d.Get("role_arns").([]interface{})
	policyARNs := d.Get("policy_arns").([]interface{})
	policyDocument := d.Get("policy_document").(string)

	policyARN := d.Get("policy_arn").(string)
	policy := d.Get("policy").(string)

	data := map[string]interface{}{}

	if credentialType != "" {
		data["credential_type"] = credentialType
		if len(roleARNs) > 0 {
			data["role_arns"] = roleARNs
		}
		if len(policyARNs) > 0 {
			data["policy_arns"] = policyARNs
		}
		if policyDocument != "" {
			data["policy_document"] = policyDocument
		}
	} else {
		if policy != "" {
			data["policy"] = policy
		}
		if policyARN != "" {
			data["arn"] = policyARN
		}
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

	if invalidData, ok := secret.Data["invalid_data"]; ok {
		log.Printf("[WARN] Role %q has Invalid Data from upgrading: %q\nSee https://www.vaultproject.io/guides/upgrading/upgrade-to-0.11.0.html#aws-secret-engine-roles for more details", path, invalidData)
	}

	if credentialTypes, ok := secret.Data["credential_types"]; ok {
		credentialTypes := credentialTypes.([]interface{})
		// Vault >= 0.11
		if len(credentialTypes) > 1 {
			log.Printf("[WARN] Role %q has multiple credential types from upgrading: %q\nSee https://www.vaultproject.io/guides/upgrading/upgrade-to-0.11.0.html#aws-secret-engine-roles for more details", path, credentialTypes)
		}

		if _, ok := d.GetOk("credential_type"); ok {
			d.Set("credential_type", credentialTypes[0])
			d.Set("policy_document", secret.Data["policy_document"])

			if err := d.Set("role_arns", secret.Data["role_arns"]); err != nil {
				return fmt.Errorf("error setting role_arns for role %q: %s", path, err)
			}
			if err := d.Set("policy_arns", secret.Data["policy_arns"]); err != nil {
				return fmt.Errorf("error setting policy_arns for role %q: %s", path, err)
			}

		} else {
			// Deprecated style
			policyARNs, hasPolicy := secret.Data["policy_arns"].([]interface{})
			roleARNs, hasRole := secret.Data["role_arns"].([]interface{})

			// If both policyARNs and roleARNs are returned
			if hasPolicy && hasRole && (len(policyARNs)+len(roleARNs)) > 1 {
				log.Printf("[WARN] Role %q has returned multiple policy or role ARNs but the deprecated `policy_arn` is used.", path)
			}

			if len(policyARNs) > 0 {
				d.Set("policy_arn", policyARNs[0])
			} else if len(roleARNs) > 0 {
				d.Set("policy_arn", roleARNs[0])
			}
			d.Set("policy", secret.Data["policy_document"])
		}
	} else {
		// Vault < 0.11
		d.Set("policy", secret.Data["policy"])
		d.Set("policy_arn", secret.Data["arn"])
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
