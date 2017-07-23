package vault

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	"strings"
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

func isOktaUserPresent(client *api.Client, path, username string) (bool, error) {
	secret, err := client.Logical().Read(oktaUserEndpoint(path, username))
	if err != nil {
		return false, err
	}

	return secret != nil, err
}

func updateOktaUser(client *api.Client, path string, user oktaUser) error {
	_, err := client.Logical().Write(oktaUserEndpoint(path, user.Username), map[string]interface{}{
		"groups":   strings.Join(user.Groups, ","),
		"policies": strings.Join(user.Policies, ","),
	})

	return err
}

func deleteOktaUser(client *api.Client, path, username string) error {
	_, err := client.Logical().Delete(oktaUserEndpoint(path, username))
	return err
}

func isOktaGroupPresent(client *api.Client, path, name string) (bool, error) {
	secret, err := client.Logical().Read(oktaGroupEndpoint(path, name))
	if err != nil {
		return false, err
	}

	return secret != nil, err
}

func updateOktaGroup(client *api.Client, path string, group oktaGroup) error {
	_, err := client.Logical().Write(oktaGroupEndpoint(path, group.Name), map[string]interface{}{
		"policies": strings.Join(group.Policies, ","),
	})

	return err
}

func deleteOktaGroup(client *api.Client, path, name string) error {
	_, err := client.Logical().Delete(oktaGroupEndpoint(path, name))
	return err
}

func oktaConfigEndpoint(path string) string {
	return fmt.Sprintf("/auth/%s/config", path)
}

func oktaUserEndpoint(path, username string) string {
	return fmt.Sprintf("/auth/%s/users/%s", path, username)
}

func oktaGroupEndpoint(path, username string) string {
	return fmt.Sprintf("/auth/%s/groups/%s", path, username)
}
