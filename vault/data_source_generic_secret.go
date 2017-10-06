package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/hashicorp/go-uuid"

	"github.com/hashicorp/terraform/helper/schema"

	"github.com/hashicorp/vault/api"
)

func genericSecretDataSource() *schema.Resource {
	return &schema.Resource{
		Read: genericSecretDataSourceRead,

		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Full path from which a secret will be read.",
			},

			"command": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "read",
				ValidateFunc: validateVaultCommand,
				Description:  "Vault command to use to get the secret.",
			},

			"wrap_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Setting this value will wrap response with specified TTL.",
			},

			"write_data_json": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "Data to send on write command.",
				ValidateFunc: ValidateDataJSON,
			},

			"data_json": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "JSON-encoded secret data read from Vault.",
			},

			"data": {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Map of strings read from Vault.",
			},

			"lease_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Lease identifier assigned by vault.",
			},

			"lease_duration": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Lease duration in seconds relative to the time in lease_start_time.",
			},

			"lease_start_time": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Time at which the lease was read, using the clock of the system where Terraform was running",
			},

			"lease_renewable": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "True if the duration of this lease can be extended through renewal.",
			},

			"wrap_information": {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "Wrapping response information",
			},
		},
	}
}

func validateVaultCommand(v interface{}, k string) (ws []string, errors []error) {
	value := v.(string)
	switch value {
	case "read", "write":
	default:
		errors = append(errors, fmt.Errorf("%s command is not supported", value))
	}
	return
}

func runVaultCommand(c *api.Client, command, path, wrapTTL string, writeData map[string]interface{}) (*api.Secret, error) {
	if wrapTTL != "" {
		c.SetWrappingLookupFunc(func(string, string) string {
			log.Printf("[DEBUG] Setting wrap TTL %s for %s", wrapTTL, path)
			return wrapTTL
		})
		defer c.SetWrappingLookupFunc(nil)
	}

	switch command {
	case "read":
		return c.Logical().Read(path)
	case "write":
		return c.Logical().Write(path, writeData)
	}
	return nil, fmt.Errorf("unsupported command %s", command)
}

func getWriteData(d *schema.ResourceData) (map[string]interface{}, error) {
	data := d.Get("write_data_json").(string)
	if len(data) == 0 {
		return nil, nil
	}
	var writeData map[string]interface{}
	err := json.Unmarshal([]byte(data), &writeData)
	if err != nil {
		return nil, fmt.Errorf("write_data_json %#v syntax error: %s", data, err)
	}
	return writeData, nil
}

func genericSecretDataSourceRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	path := d.Get("path").(string)

	log.Printf("[DEBUG] Reading %s from Vault", path)

	command := d.Get("command").(string)
	wrapTTL := d.Get("wrap_ttl").(string)

	writeData, err := getWriteData(d)
	if err != nil {
		return err
	}

	secret, err := runVaultCommand(client, command, path, wrapTTL, writeData)
	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}
	if secret == nil {
		return fmt.Errorf("no secret found at %q", path)
	}

	id := secret.RequestID
	if id == "" {
		// Wrapped responses don't have a request ID
		id, err = uuid.GenerateUUID()
		if err != nil {
			return fmt.Errorf("couldn't generate an uuid: %s", err)
		}
	}
	d.SetId(id)

	// Ignoring error because this value came from JSON in the
	// first place so no reason why it should fail to re-encode.
	jsonDataBytes, _ := json.Marshal(secret.Data)
	d.Set("data_json", string(jsonDataBytes))

	// Since our "data" map can only contain string values, we
	// will take strings from Data and write them in as-is,
	// and write everything else in as a JSON serialization of
	// whatever value we get so that complex types can be
	// passed around and processed elsewhere if desired.
	dataMap := map[string]string{}
	for k, v := range secret.Data {
		if vs, ok := v.(string); ok {
			dataMap[k] = vs
		} else {
			// Again ignoring error because we know this value
			// came from JSON in the first place and so must be valid.
			vBytes, _ := json.Marshal(v)
			dataMap[k] = string(vBytes)
		}
	}
	d.Set("data", dataMap)

	d.Set("lease_id", secret.LeaseID)
	d.Set("lease_duration", secret.LeaseDuration)
	d.Set("lease_start_time", time.Now().Format("RFC3339"))
	d.Set("lease_renewable", secret.Renewable)

	if secret.WrapInfo != nil {
		wrapInfo := map[string]string{
			"token":            secret.WrapInfo.Token,
			"ttl":              strconv.Itoa(secret.WrapInfo.TTL),
			"creation_time":    secret.WrapInfo.CreationTime.Format("RFC3339"),
			"wrapped_accessor": secret.WrapInfo.WrappedAccessor,
		}
		d.Set("wrap_information", wrapInfo)
	}

	return nil
}
