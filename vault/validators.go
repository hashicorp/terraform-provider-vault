package vault

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gosimple/slug"
)

func validateStringSlug(i interface{}, k string) (s []string, es []error) {
	v, ok := i.(string)
	if !ok {
		es = append(es, fmt.Errorf("expected type of %s to be string", k))
		return
	}

	if !slug.IsSlug(v) {
		es = append(es, fmt.Errorf("expected %s to be a slugified value, i.e: 'my-slug-without-spaces'", k))
	}
	return
}

func validateDuration(i interface{}, k string) (s []string, es []error) {
	v, ok := i.(string)
	if !ok {
		es = append(es, fmt.Errorf("expected type of %s to be string", k))
		return
	}

	if _, err := time.ParseDuration(v); err != nil {
		es = append(es, fmt.Errorf("expected '%s' to be a valid duration string", k))
	}
	return
}

func validateNoTrailingSlash(i interface{}, k string) (s []string, es []error) {
	v, ok := i.(string)
	if !ok {
		es = append(es, fmt.Errorf("expected type of %s to be string", k))
		return
	}

	if strings.HasSuffix(v, "/") {
		es = append(es, errors.New("cannot write to a path ending in '/'"))
	}
	return
}
