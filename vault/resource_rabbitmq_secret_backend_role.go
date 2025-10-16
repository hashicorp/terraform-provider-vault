// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/hashicorp/terraform-provider-vault/internal/provider"
)

func rabbitMQSecretBackendRoleResource() *schema.Resource {
	return &schema.Resource{
		Create: rabbitMQSecretBackendRoleWrite,
		Read:   provider.ReadWrapper(rabbitMQSecretBackendRoleRead),
		Update: rabbitMQSecretBackendRoleWrite,
		Delete: rabbitMQSecretBackendRoleDelete,
		Exists: rabbitMQSecretBackendRoleExists,
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

func rabbitMQSecretBackendRoleWrite(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	backend := d.Get("backend").(string)
	name := d.Get("name").(string)
	tags := d.Get("tags").(string)

	vhostsJSON, _, err := expandRabbitMQSecretBackendRoleVhost(d.Get("vhost").([]interface{}), "host")
	if err != nil {
		return fmt.Errorf("error expanding vhost: %w", err)
	}
	vhostTopicsJSON, err := expandRabbitMQSecretBackendRoleVhostTopic(d.Get("vhost_topic").([]interface{}))
	if err != nil {
		return fmt.Errorf("error expanding vhost_topic: %w", err)
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
	return rabbitMQSecretBackendRoleRead(d, meta)
}

func rabbitMQSecretBackendRoleRead(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

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

	if vhosts, ok := secret.Data["vhosts"]; ok && vhosts != nil {
		if err := d.Set("vhost", flattenRabbitMQSecretBackendRoleVhost(vhosts.(map[string]interface{}))); err != nil {
			return fmt.Errorf("error setting vhosts in state: %w", err)
		}
	}

	if vhostTopics, ok := secret.Data["vhost_topics"]; ok && vhostTopics != nil {
		if err := d.Set("vhost_topic", flattenRabbitMQSecretBackendRoleVhostTopics(vhostTopics.(map[string]interface{}))); err != nil {
			return fmt.Errorf("error setting vhosts topics in state: %w", err)
		}
	}

	return nil
}

func rabbitMQSecretBackendRoleDelete(d *schema.ResourceData, meta interface{}) error {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return e
	}

	path := d.Id()
	log.Printf("[DEBUG] Deleting role %q", path)
	_, err := client.Logical().Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting role %q: %w", path, err)
	}
	log.Printf("[DEBUG] Deleted role %q", path)
	return nil
}

func rabbitMQSecretBackendRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	client, e := provider.GetClient(d, meta)
	if e != nil {
		return false, e
	}

	path := d.Id()
	log.Printf("[DEBUG] Checking if %q exists", path)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return true, fmt.Errorf("error checking if %q exists: %s", path, err)
	}
	log.Printf("[DEBUG] Checked if %q exists", path)
	return secret != nil, nil
}

func expandRabbitMQSecretBackendRoleVhost(vhost []interface{}, key string) (string, map[string]interface{}, error) {
	log.Printf("[DEBUG] Vhosts as list from ResourceData: %+v", vhost)

	vhosts := make(map[string]interface{}, len(vhost))

	for _, host := range vhost {
		h := map[string]interface{}{}
		var id string
		for k, v := range host.(map[string]interface{}) {
			if k == key {
				id = v.(string)
				continue
			}
			h[k] = v
		}
		if id == "" {
			return "", nil, fmt.Errorf("empty vhost")
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

func expandRabbitMQSecretBackendRoleVhostTopic(vhost []interface{}) (string, error) {
	log.Printf("[DEBUG] Vhosts as list from ResourceData: %+v", vhost)

	vhosts := make(map[string]interface{}, len(vhost))

	for _, host := range vhost {
		vv := host.(map[string]interface{})
		id := vv["host"].(string)

		_, topics, err := expandRabbitMQSecretBackendRoleVhost(vv["vhost"].([]interface{}), "topic")
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

func flattenRabbitMQSecretBackendRoleVhost(vhost map[string]interface{}) []map[string]interface{} {
	var vhosts []map[string]interface{}

	// Get sorted keys
	keys := make([]string, 0, len(vhost))
	for k := range vhost {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Process in sorted order
	for _, id := range keys {
		vals := vhost[id].(map[string]interface{})
		vhosts = append(vhosts, map[string]interface{}{
			"host":      id,
			"configure": vals["configure"],
			"write":     vals["write"],
			"read":      vals["read"],
		})
	}

	return vhosts
}

func flattenRabbitMQSecretBackendRoleVhostTopics(vhostTopic map[string]interface{}) []map[string]interface{} {
	var vhostTopics []map[string]interface{}
	for id, val := range vhostTopic {
		vals := val.(map[string]interface{})

		vhostTopics = append(vhostTopics, map[string]interface{}{
			"host":  id,
			"vhost": flattenRabbitMQSecretBackendRoleVhostTopic(vals),
		})
	}

	return vhostTopics
}

func flattenRabbitMQSecretBackendRoleVhostTopic(topic map[string]interface{}) []map[string]interface{} {
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