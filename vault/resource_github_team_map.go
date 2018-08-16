package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/vault/api"
)

func GithubTeamMap() *schema.Resource {
	return &schema.Resource{
		Create: GithubTeamMapCreate,
		Update: GithubTeamMapCreate,
		Delete: GithubTeamMapRemove,
		Read:   GithubTeamMapRead,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the GithubTeam",
			},

			"policies": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				Description: "The list of policies to map",
			},
		},
	}
}

func GithubTeamMapCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Get("name").(string)
	policies := d.Get("policies").(string)

	log.Printf("[DEBUG] Mapping team to policy %s to Vault", name)
	err := client.Sys().PostGithubTeamMap(name, policies)

	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}

	d.SetId(name)

	return nil
}

func GithubTeamMapRemove(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Get("name").(string)

	log.Printf("[DEBUG] Deleting github map policy %s from Vault", name)

	err := client.Sys().DeleteGithubTeamMap(name)
	if err != nil {
		return fmt.Errorf("error deleting from Vault: %s", err)
	}

	return nil
}

func GithubTeamMapRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Id()

	policy, err := client.Sys().GetGithubTeamMap(name)

	if err != nil {
		return fmt.Errorf("error reading from map Vault: %s", err)
	}
	d.Set("policies", policy)
	d.Set("name", name)
	return nil
}
