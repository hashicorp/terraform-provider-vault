package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func rabbitmqSecretBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		Create: rabbitmqSecretBackendRoleWrite,
		Read:   rabbitmqSecretBackendRoleRead,
		Update: rabbitmqSecretBackendRoleWrite,
		Delete: rabbitmqSecretBackendRoleDelete,
		Exists: rabbitmqSecretBackendRoleExists,
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
				Description: "The path of the Rabbitmq Secret Backend the role belongs to.",
			},
			"tags": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				Description: "Specifies a comma-separated RabbitMQ management tags.",
			},
			"vhost": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Specifies a map of virtual hosts to permissions.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"host": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The vhost to set permissions for.",
						},
						"configure": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The configure permissions for this vhost.",
						},
						"read": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The read permissions for this vhost.",
						},
						"write": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The write permissions for this vhost.",
						},
					},
				},
			},
			"vhost_topic": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Specifies a map of virtual hosts and exchanges to topic permissions. This option requires RabbitMQ 3.7.0 or later.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"vhost": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "Specifies a map of virtual hosts to permissions.",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"topic": {
										Type:        schema.TypeString,
										Required:    true,
										Description: "The vhost to set permissions for.",
									},
									"read": {
										Type:        schema.TypeString,
										Required:    true,
										Description: "The read permissions for this vhost.",
									},
									"write": {
										Type:        schema.TypeString,
										Required:    true,
										Description: "The write permissions for this vhost.",
									},
								},
							},
						},
						"host": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The vhost to set permissions for.",
						},
					},
				},
			},
		},
	}
}

func rabbitmqSecretBackendRoleWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)
	tags := d.Get("tags").(string)

	vhostsJSON, _, err := expandRabbitmqSecretBackendRoleVhost(d.Get("vhost").([]interface{}), "host")
	if err != nil {
		return err
	}
	vhostTopicsJSON, err := expandRabbitmqSecretBackendRoleVhostTopic(d.Get("vhost_topic").([]interface{}))
	if err != nil {
		return err
	}

	data := map[string]interface{}{
		"tags":         tags,
		"vhosts":       vhostsJSON,
		"vhost_topics": vhostTopicsJSON,
	}
	log.Printf("[DEBUG] Creating role %q on Rabbitmq backend %q", name, backend)
	_, err = client.Logical().Write(backend+"/roles/"+name, data)
	if err != nil {
		return fmt.Errorf("error creating role %q for backend %q: %w", name, backend, err)
	}
	log.Printf("[DEBUG] Created role %q on Rabbitmq backend %q", name, backend)

	d.SetId(backend + "/roles/" + name)
	return rabbitmqSecretBackendRoleRead(d, meta)
}

func rabbitmqSecretBackendRoleRead(d *schema.ResourceData, meta interface{}) error {
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

	d.Set("tags", secret.Data["tags"])
	d.Set("backend", strings.Join(pathPieces[:len(pathPieces)-2], "/"))
	d.Set("name", pathPieces[len(pathPieces)-1])

	if err := d.Set("vhost", flattenRabbitmqSecretBackendRoleVhost(secret.Data["vhosts"].(map[string]interface{}))); err != nil {
		return fmt.Errorf("Error setting vhosts in state: %w", err)
	}

	if err := d.Set("vhost_topic", flattenRabbitmqSecretBackendRoleVhostTopics(secret.Data["vhost_topics"].(map[string]interface{}))); err != nil {
		return fmt.Errorf("Error setting vhosts topics in state: %w", err)
	}

	return nil
}

func rabbitmqSecretBackendRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Id()
	log.Printf("[DEBUG] Deleting role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting role %q: %w", path, err)
	}
	log.Printf("[DEBUG] Deleted role %q", path)
	return nil
}

func rabbitmqSecretBackendRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
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

func expandRabbitmqSecretBackendRoleVhost(vhost []interface{}, typ string) (string, map[string]interface{}, error) {
	log.Printf("[DEBUG] Vhosts as list from ResourceData: %+v", vhost)

	vhosts := make(map[string]interface{}, len(vhost))

	for _, host := range vhost {
		h := map[string]interface{}{}
		var id string
		for k, v := range host.(map[string]interface{}) {
			if k == typ {
				id = v.(string)
				continue
			}
			h[k] = v
		}
		vhosts[id] = h
	}

	log.Printf("[DEBUG] vhosts after munging: %+v", vhosts)

	vhostsJSON, err := json.Marshal(vhosts)
	if err != nil {
		return "", nil, fmt.Errorf("error serializing vhosts: %w", err)
	}

	log.Printf("[DEBUG] vhosts as JSON: %+v", string(vhostsJSON))

	return string(vhostsJSON), vhosts, nil
}

func expandRabbitmqSecretBackendRoleVhostTopic(vhost []interface{}) (string, error) {
	log.Printf("[DEBUG] Vhosts as list from ResourceData: %+v", vhost)

	vhosts := make(map[string]interface{}, len(vhost))

	for _, host := range vhost {
		vv := host.(map[string]interface{})
		id := vv["host"].(string)

		_, topics, err := expandRabbitmqSecretBackendRoleVhost(vv["vhost"].([]interface{}), "topic")
		if err != nil {
			return "", err
		}

		vhosts[id] = topics
	}

	log.Printf("[DEBUG] vhost topics after munging: %+v", vhosts)

	vhostsJSON, err := json.Marshal(vhosts)
	if err != nil {
		return "", fmt.Errorf("error serializing vhosts: %w", err)
	}

	log.Printf("[DEBUG] vhost topics as JSON: %+v", string(vhostsJSON))

	return string(vhostsJSON), nil
}

func flattenRabbitmqSecretBackendRoleVhost(vhost map[string]interface{}) []map[string]interface{} {
	var vhosts []map[string]interface{}
	for id, val := range vhost {
		vals := val.(map[string]interface{})
		vhosts = append(vhosts, map[string]interface{}{
			"host":      id,
			"configure": vals["configure"],
			"write":     vals["write"],
			"read":      vals["read"],
		})
	}

	return vhosts
}

func flattenRabbitmqSecretBackendRoleVhostTopics(vhostTopic map[string]interface{}) []map[string]interface{} {
	var vhostTopics []map[string]interface{}
	for id, val := range vhostTopic {
		vals := val.(map[string]interface{})

		log.Printf("lol: %+v", vals)
		log.Printf("lol2: %+v", id)

		vhostTopics = append(vhostTopics, map[string]interface{}{
			"host":  id,
			"vhost": flattenRabbitmqSecretBackendRoleVhostTopic(vals),
		})
	}

	return vhostTopics
}

func flattenRabbitmqSecretBackendRoleVhostTopic(topic map[string]interface{}) []map[string]interface{} {
	var topics []map[string]interface{}
	for id, val := range topic {
		vals := val.(map[string]interface{})
		topics = append(topics, map[string]interface{}{
			"topic": id,
			"write": vals["write"],
			"read":  vals["read"],
		})
	}

	return topics
}
