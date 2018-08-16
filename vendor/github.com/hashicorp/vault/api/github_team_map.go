package api

import (
	"fmt"

	"github.com/mitchellh/mapstructure"
)

func (c *Sys) GetGithubTeamMap(team_name string) (string, error) {
	r := c.c.NewRequest("GET", fmt.Sprintf("/v1/auth/github/map/teams/%s", team_name))
	resp, err := c.c.RawRequest(r)
	if resp != nil {
		defer resp.Body.Close()
		if resp.StatusCode == 404 {
			return "", nil
		}
	}
	if err != nil {
		return "", err
	}

	var result map[string]interface{}
	err = resp.DecodeJSON(&result)
	if err != nil {
		return "", err
	}

	var ok bool
	if _, ok = result["data"]; !ok {
		return "", fmt.Errorf("policies mapped to group not found in response")
	}

	return result["data"].(string), nil
}

func (c *Sys) PostGithubTeamMap(team_name, policies string) error {
	body := map[string]string{
		"value": policies,
	}

	r := c.c.NewRequest("POST", fmt.Sprintf("/v1/auth/github/map/teams/%s", team_name))
	if err := r.SetJSONBody(body); err != nil {
		return err
	}

	resp, err := c.c.RawRequest(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}