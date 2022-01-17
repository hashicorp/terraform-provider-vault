package vault

import (
	"fmt"
	"regexp"
	"time"

	"github.com/gosimple/slug"
)

const pathDelim = "/"

var (
	regexpPathLeading  = regexp.MustCompile(fmt.Sprintf(`^%s`, pathDelim))
	regexpPathTrailing = regexp.MustCompile(fmt.Sprintf(`%s$`, pathDelim))
	regexpPath         = regexp.MustCompile(fmt.Sprintf(`%s|%s`, regexpPathLeading, regexpPathTrailing))
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

func validateNoTrailingSlash(i interface{}, k string) ([]string, []error) {
	var errs []error
	if err := checkPath(regexpPathTrailing, i, k); err != nil {
		errs = append(errs, err)
	}

	return nil, errs
}

func validateNamespace(i interface{}, k string) ([]string, []error) {
	var errs []error
	if err := checkPath(regexpPath, i, k); err != nil {
		errs = append(errs, err)
	}

	return nil, errs
}

func checkPath(r *regexp.Regexp, i interface{}, k string) error {
	v, ok := i.(string)
	if !ok {
		return fmt.Errorf("value for %q must be string, not %T", k, i)
	}

	if v == "" {
		return fmt.Errorf("value for %q cannot be empty", k)
	}

	if r.MatchString(v) {
		return fmt.Errorf("invalid value %q for %q, contains leading/trailing %q", v, k, pathDelim)
	}

	return nil
}
