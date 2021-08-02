package vault

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-provider-vault/util"
)

type oktaUser struct {
	Username string
	Groups   []string
	Policies []string
}

type oktaGroup struct {
	Name     string
	Policies []string
}

func isOktaUserPresent(client *util.Client, path, username string) (bool, error) {
	secret, err := client.Logical().Read(oktaUserEndpoint(path, username))
	if err != nil {
		return false, err
	}

	return secret != nil, err
}

func listOktaUsers(client *util.Client, path string) ([]string, error) {
	secret, err := client.Logical().List(oktaUserEndpoint(path, ""))
	if err != nil {
		return []string{}, err
	}

	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	if v, ok := secret.Data["keys"]; ok {
		return util.ToStringArray(v.([]interface{})), nil
	}

	return []string{}, nil
}

func readOktaUser(client *util.Client, path string, username string) (*oktaUser, error) {
	secret, err := client.Logical().Read(oktaUserEndpoint(path, username))
	if err != nil {
		return nil, err
	}

	return &oktaUser{
		Username: username,
		Groups:   util.ToStringArray(secret.Data["groups"].([]interface{})),
		Policies: util.ToStringArray(secret.Data["policies"].([]interface{})),
	}, nil
}

func updateOktaUser(client *util.Client, path string, user oktaUser) error {
	_, err := client.Logical().Write(oktaUserEndpoint(path, user.Username), map[string]interface{}{
		"groups":   strings.Join(user.Groups, ","),
		"policies": strings.Join(user.Policies, ","),
	})

	return err
}

func deleteOktaUser(client *util.Client, path, username string) error {
	_, err := client.Logical().Delete(oktaUserEndpoint(path, username))
	return err
}

func isOktaAuthBackendPresent(client *util.Client, path string) (bool, error) {
	auths, err := client.Sys().ListAuth()
	if err != nil {
		return false, fmt.Errorf("error reading from Vault: %s", err)
	}

	configuredPath := path + "/"

	for authBackendPath, auth := range auths {
		if auth.Type == "okta" && authBackendPath == configuredPath {
			return true, nil
		}
	}

	return false, nil
}

func isOktaGroupPresent(client *util.Client, path, name string) (bool, error) {
	secret, err := client.Logical().Read(oktaGroupEndpoint(path, name))
	if err != nil {
		return false, err
	}

	return secret != nil, err
}

func listOktaGroups(client *util.Client, path string) ([]string, error) {
	secret, err := client.Logical().List(oktaGroupEndpoint(path, ""))
	if err != nil {
		return []string{}, err
	}

	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	if v, ok := secret.Data["keys"]; ok {
		return util.ToStringArray(v.([]interface{})), nil
	}

	return []string{}, nil
}

func readOktaGroup(client *util.Client, path string, name string) (*oktaGroup, error) {
	secret, err := client.Logical().Read(oktaGroupEndpoint(path, name))
	if err != nil {
		return nil, err
	}

	return &oktaGroup{
		Name:     name,
		Policies: util.ToStringArray(secret.Data["policies"].([]interface{})),
	}, nil
}

func updateOktaGroup(client *util.Client, path string, group oktaGroup) error {
	_, err := client.Logical().Write(oktaGroupEndpoint(path, group.Name), map[string]interface{}{
		"policies": strings.Join(group.Policies, ","),
	})

	return err
}

func deleteOktaGroup(client *util.Client, path, name string) error {
	_, err := client.Logical().Delete(oktaGroupEndpoint(path, name))
	return err
}

func oktaConfigEndpoint(path string) string {
	return fmt.Sprintf("/auth/%s/config", path)
}

func oktaUserEndpoint(path, username string) string {
	return fmt.Sprintf("/auth/%s/users/%s", path, username)
}

func oktaGroupEndpoint(path, groupName string) string {
	return fmt.Sprintf("/auth/%s/groups/%s", path, groupName)
}
