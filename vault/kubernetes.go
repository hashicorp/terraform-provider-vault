package vault

import (
	"fmt"
	"log"

	"github.com/hashicorp/vault/api"
)

type kubernetesConfig struct {
	Host             string
	CACert           string
	TokenReviewerJWT string
	PEMKeys          []string
}

func kubernetesConfigEndpoint(path string) string {
	return fmt.Sprintf("/auth/%s/config", path)
}

func readKubernetesConfig(client *api.Client, path string) (*kubernetesConfig, error) {
	response, err := client.Logical().Read(kubernetesConfigEndpoint(path))
	if err != nil {
		return nil, err
	}

	if response != nil && response.Data != nil {
		host, _ := response.Data["kubernetes_host"].(string)
		caCert, _ := response.Data["kubernetes_ca_cert"].(string)
		tokenReviewerJWT, _ := response.Data["token_reviewer_jwt"].(string)
		pemKeys, _ := response.Data["pem_keys"].([]interface{})
		pemKeyArray := make([]string, len(pemKeys))
		for i, v := range pemKeys {
			pemKeyArray[i] = v.(string)
		}

		return &kubernetesConfig{
			Host:             host,
			CACert:           caCert,
			TokenReviewerJWT: tokenReviewerJWT,
			PEMKeys:          pemKeyArray,
		}, nil
	}

	return nil, nil
}

func updateKubernetesConfig(client *api.Client, path string, config kubernetesConfig) error {
	_, err := client.Logical().Write(kubernetesConfigEndpoint(path), map[string]interface{}{
		"kubernetes_host":    config.Host,
		"kubernetes_ca_cert": config.CACert,
		"token_reviewer_jwt": config.TokenReviewerJWT,
		"pem_keys":           config.PEMKeys,
	})

	return err
}

type kubernetesRole struct {
	Name            string
	ServiceAccounts []string
	Namespaces      []string
	TTL             string
	MaxTTL          string
	Period          string
	Policies        []string
}

func kubernetesRoleEndpoint(path, role string) string {
	return fmt.Sprintf("/auth/%s/role/%s", path, role)
}

func readKubernetesRole(client *api.Client, path string, role string) (*kubernetesRole, error) {
	response, err := client.Logical().Read(kubernetesRoleEndpoint(path, role))
	if err != nil {
		return nil, err
	}

	if response != nil && response.Data != nil {
		log.Printf("[DEBUG] %+v\n", response)
		serviceAccounts, _ := response.Data["bound_service_account_names"].([]interface{})
		serviceAccountArray := make([]string, len(serviceAccounts))
		for i, v := range serviceAccounts {
			serviceAccountArray[i] = v.(string)
		}
		namespaces, _ := response.Data["bound_service_account_namespaces"].([]interface{})
		namespaceArray := make([]string, len(namespaces))
		for i, v := range namespaces {
			namespaceArray[i] = v.(string)
		}
		ttl, _ := response.Data["ttl"].(string)
		maxTTL, _ := response.Data["max_ttl"].(string)
		period, _ := response.Data["period"].(string)
		policies, _ := response.Data["policies"].([]interface{})
		policyArray := make([]string, len(policies))
		for i, v := range policies {
			policyArray[i] = v.(string)
		}

		return &kubernetesRole{
			Name:            role,
			ServiceAccounts: serviceAccountArray,
			Namespaces:      namespaceArray,
			TTL:             ttl,
			MaxTTL:          maxTTL,
			Period:          period,
			Policies:        policyArray,
		}, nil
	}

	return nil, nil
}

func updateKubernetesRole(client *api.Client, path string, role kubernetesRole) error {
	_, err := client.Logical().Write(kubernetesRoleEndpoint(path, role.Name), map[string]interface{}{
		"bound_service_account_names":      role.ServiceAccounts,
		"bound_service_account_namespaces": role.Namespaces,
		"ttl":      role.TTL,
		"max_ttl":  role.MaxTTL,
		"period":   role.Period,
		"policies": role.Policies,
	})

	return err
}
