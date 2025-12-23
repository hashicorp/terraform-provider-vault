package sys

import (
	"testing"

	fuzz "github.com/google/gofuzz"
	"github.com/stretchr/testify/require"
)

func TestModelConversion(t *testing.T) {
	f := fuzz.New()
	var a1, a2 ManagedKeyEntryPKCSAPIModel
	var m ManagedKeyEntryPKCS
	f.Fuzz(&a1)

	require.NoError(t, apiModelToModel(a1, &m))
	require.NoError(t, modelToApiModel(m, &a2))
	require.Equal(t, a1, a2)
}
